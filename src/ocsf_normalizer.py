"""Convert Entra-like sign-in events into OCSF Authentication events."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVENTS_IN = ROOT / "data" / "generated" / "events_seed42_attacks.jsonl"
EVENTS_OUT = ROOT / "data" / "normalized" / "ocsf_authentication_seed42_attacks.jsonl"
OCSF_VERSION = "1.4.0"


def read_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, sort_keys=True) + "\n")


def epoch_ms(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return int(timestamp.timestamp() * 1000)


def os_detail(value):
    names = {"Windows": 100, "Linux": 200, "Android": 201, "macOS": 300, "iOS": 301}
    for name, type_id in names.items():
        if value.lower().startswith(name.lower()):
            return {"name": name, "type": name, "type_id": type_id, "version": value}
    return {"name": value or "Unknown"}


def outcome(event):
    status = event.get("status", {})
    success = status.get("errorCode") == 0
    risk = event.get("riskLevelDuringSignIn", "none")
    severity_id = {"none": 1, "low": 2, "medium": 3, "high": 4}.get(risk, 1)
    if not success:
        severity_id = max(severity_id, 2)
    severity = {1: "Informational", 2: "Low", 3: "Medium", 4: "High"}[severity_id]
    return success, severity_id, severity


def user(event, is_mfa):
    principal = event["userPrincipalName"]
    return {
        "uid": event["userId"],
        "name": principal.split("@", 1)[0],
        "email_addr": principal,
        "display_name": event.get("userDisplayName"),
        "has_mfa": is_mfa,
        "type_id": 1,
        "type": "User",
    }


def source_endpoint(event):
    device = event.get("deviceDetail", {})
    return {
        "ip": event.get("ipAddress"),
        "uid": device.get("deviceId"),
        "name": device.get("displayName"),
        "os": os_detail(device.get("operatingSystem", "")),
        "location": {"country": event.get("location", {}).get("countryOrRegion", "")},
    }


def normalize(event):
    success, severity_id, severity = outcome(event)
    time = epoch_ms(event["createdDateTime"])
    is_mfa = event.get("authenticationRequirement") == "multiFactorAuthentication"
    status = event.get("status", {})
    detail = status.get("additionalDetails") or status.get("failureReason") or ""

    return {
        "activity_id": 1,
        "activity_name": "Logon",
        "auth_protocol_id": 0,
        "auth_protocol": "Unknown",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": 3002,
        "class_name": "Authentication",
        "is_mfa": is_mfa,
        "is_new_logon": True,
        "is_remote": True,
        "logon_type_id": 99,
        "logon_type": "Interactive" if event.get("isInteractive") else "Non-interactive",
        "message": f"{event['userPrincipalName']} logon {'succeeded' if success else 'failed'} to {event['appDisplayName']}",
        "metadata": {
            "uid": event["id"],
            "correlation_uid": event.get("correlationId"),
            "product": {"name": "Microsoft Entra ID", "vendor_name": "Microsoft"},
            "log_provider": "PseudoTracer",
            "original_time": event['createdDateTime'],
            "tenant_uid": "contoso.example",
            "version": OCSF_VERSION,
        },
        "service": {"name": event["appDisplayName"], "uid": event.get("resourceId")},
        "session": {
            "uid": event.get("sessionId"),
            "created_time": time,
            "issuer": "Microsoft Entra ID",
            "is_mfa": is_mfa,
            "is_remote": True,
        },
        "severity_id": severity_id,
        "severity": severity,
        "src_endpoint": source_endpoint(event),
        "status_id": 1 if success else 2,
        "status": "Success" if success else "Failure",
        "status_code": str(status.get("errorCode", "")),
        "status_detail": detail,
        "time": time,
        "timezone_offset": 0,
        "type_uid": 300201,
        "type_name": "Authentication: Logon",
        "unmapped": {
            "entra": {
                "app_id": event.get("appId"),
                "authentication_details": event.get("authenticationDetails", []),
                "client_app_used": event.get("clientAppUsed"),
                "conditional_access_status": event.get("conditionalAccessStatus"),
                "device_browser": event.get("deviceDetail", {}).get("browser"),
                "device_type": event.get("deviceDetail", {}).get("deviceType", "unknown"),
                "device_compliant": event.get("deviceDetail", {}).get("isCompliant"),
                "device_managed": event.get("deviceDetail", {}).get("isManaged"),
                "device_trust_type": event.get("deviceDetail", {}).get("trustType"),
                "identity_context": event.get("identityContext", {}),
                "risk_events": event.get("riskEventTypes_v2", []),
                "risk_level_aggregated": event.get("riskLevelAggregated"),
                "risk_score": event.get("riskScore"),
                "risk_state": event.get("riskState"),
                "round_trip_time_ms": event.get("roundTripTimeMs"),
                "user_agent": event.get("userAgent"),
            }
        },
        "user": user(event, is_mfa),
    }


def validate(events):
    required = {"time", "metadata", "service", "session", "src_endpoint", "user"}
    seen = set()
    for event in events:
        missing = required - event.keys()
        uid = event.get('metadata', {}).get('uid')
        if missing or event.get("class_uid") != 3002 or not uid or uid in seen:
            raise ValueError(f"Invalid OCSF event: {event.get('metadata', {}).get('uid')}")
        seen.add(uid)


def main():
    parser = argparse.ArgumentParser(description="Normalize Entra-like sign-in events to OCSF Authentication.")
    parser.add_argument("--events-in", type=Path, default=EVENTS_IN)
    parser.add_argument("--events-out", type=Path, default=EVENTS_OUT)
    args = parser.parse_args()

    events = [normalize(event) for event in read_jsonl(args.events_in)]
    validate(events)
    write_jsonl(args.events_out, events)
    print(f"Wrote {len(events)} OCSF Authentication events to {args.events_out}")


if __name__ == "__main__":
    main()
