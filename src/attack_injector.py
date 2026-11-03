"""Inject configured sequences and keep their labels in an evaluation sidecar."""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "configs" / "attacks"
EVENTS_IN = ROOT / "data" / "generated" / "events_seed42.jsonl"
SEED = 42

ATTACK_FILES = {
    "password_spray": "password_spray.yaml",
    "mfa_fatigue": "mfa_fatigue.yaml",
    "impossible_travel": "impossible_travel.yaml",
    "credential_compromise": "credential_compromise.yaml",
}


def guid(value):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"pseudotracer-{value}"))


def read_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def read_config(name, config_dir=CONFIG_DIR):
    path = config_dir / ATTACK_FILES[name]
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def as_time(value):
    value = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    # Injectors use naive UTC internally and serialize a single trailing Z.
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def app_ids(events, app_name):
    for event in events:
        if event["appDisplayName"] == app_name:
            return event["appId"], event["resourceId"]
    return guid(f"app-{app_name}"), guid(f"resource-{app_name}")


def users_from(events):
    users = {}
    for event in events:
        details = event.get("authenticationDetails", [])
        mfa = details[1]["authenticationMethod"] if len(details) > 1 else "pushNotification"
        normal_device = dict(event["deviceDetail"])
        normal_device.setdefault("roundTripTimeMs", event.get("roundTripTimeMs") or 75)
        users[event["userPrincipalName"]] = {
            "userId": event["userId"],
            "userPrincipalName": event["userPrincipalName"],
            "userDisplayName": event["userDisplayName"],
            "mfaMethod": mfa,
            "identityContext": event.get("identityContext", {}),
            "normalIp": event["ipAddress"],
            "normalCountry": event["location"]["countryOrRegion"],
            "normalDevice": normal_device,
            "normalUserAgent": event["userAgent"],
        }
    return users


def target_user(users, cfg):
    configured = cfg["target_user"]
    return users.get(configured, users[sorted(users)[0]])


def attacker_device(cfg):
    return {
        "deviceId": guid(cfg["device_id"]),
        "displayName": cfg["device_display_name"],
        "operatingSystem": cfg["operating_system"],
        "browser": cfg["browser"],
        "deviceType": cfg["device_type"],
        "roundTripTimeMs": cfg.get("round_trip_time_ms", 110 if cfg["device_type"] == "mobile" else 45),
        "isManaged": False,
        "isCompliant": False,
        "trustType": "Unknown",
    }


def status_block(success, reason):
    if success:
        return {"errorCode": 0, "failureReason": "Other.", "additionalDetails": "Success"}
    if reason == "mfa_denied":
        return {
            "errorCode": 500121,
            "failureReason": "Authentication failed during strong authentication request.",
            "additionalDetails": "MFA request was denied or expired.",
        }
    return {
        "errorCode": 50126,
        "failureReason": "Invalid username or password.",
        "additionalDetails": "The username or password is incorrect.",
    }


def risk_level(score):
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "none"


def signin_event(user, app_name, app_id, resource_id, timestamp, ip, country, device, user_agent, password_ok, mfa_ok, risk, risk_events, reason="bad_password"):
    success = password_ok and mfa_ok is not False
    auth_steps = [{"authenticationMethod": "Password", "succeeded": password_ok}]
    if password_ok and mfa_ok is not None:
        auth_steps.append({"authenticationMethod": user["mfaMethod"], "succeeded": mfa_ok})

    level = risk_level(risk)
    return {
        "id": None,
        "createdDateTime": timestamp.isoformat() + "Z",
        "userId": user["userId"],
        "userPrincipalName": user["userPrincipalName"],
        "userDisplayName": user["userDisplayName"],
        "appId": app_id,
        "appDisplayName": app_name,
        "resourceId": resource_id,
        "resourceDisplayName": app_name,
        "ipAddress": ip,
        "clientAppUsed": "Browser",
        "correlationId": None,
        "conditionalAccessStatus": "success" if success else "notApplied",
        "isInteractive": True,
        "authenticationRequirement": "multiFactorAuthentication" if mfa_ok is not None else "singleFactorAuthentication",
        "authenticationDetails": auth_steps,
        "status": status_block(success, reason),
        "deviceDetail": device,
        "location": {"city": "", "state": "", "countryOrRegion": country},
        "riskDetail": risk_events[0] if risk_events else "none",
        "riskLevelAggregated": level,
        "riskLevelDuringSignIn": level,
        "riskState": "atRisk" if risk_events else "none",
        "riskEventTypes_v2": risk_events,
        "userAgent": user_agent,
        "roundTripTimeMs": device.get("roundTripTimeMs") or 75,
        "identityContext": user["identityContext"],
        "riskScore": risk,
    }


def label(event, cfg, stage, session_hint=None, correlation_hint=None):
    event["_truth"] = {
        "incident_id": cfg.get("incident_id"),
        "scenario": cfg["scenario"],
        "attack_stage": stage,
        "is_attack": True,
    }
    if session_hint:
        event["_session_hint"] = session_hint
    if correlation_hint:
        event["_correlation_hint"] = correlation_hint
    return event


def password_spray(rng, events, users, cfg):
    app_id, resource_id = app_ids(events, cfg["app_display_name"])
    device = attacker_device(cfg)
    targets = rng.sample(sorted(users), min(cfg["target_user_count"], len(users)))
    t = as_time(cfg["start"])
    attempt_gap = timedelta(seconds=cfg["seconds_between_attempts"])
    round_gap = timedelta(minutes=cfg["minutes_between_rounds"])
    out = []

    for round_no in range(1, cfg["spray_rounds"] + 1):
        corr = guid(f"{cfg['incident_id']}-round-{round_no}")
        for principal_name in targets:
            event = signin_event(
                users[principal_name],
                cfg["app_display_name"],
                app_id,
                resource_id,
                t,
                cfg["attacker_ip"],
                cfg["attacker_country"],
                device,
                cfg["user_agent"],
                password_ok=False,
                mfa_ok=None,
                risk=85,
                risk_events=["maliciousIPAddress"],
            )
            out.append(label(event, cfg, "password_spray_failure", correlation_hint=corr))
            t += attempt_gap
        t += round_gap
    return out


def mfa_fatigue(rng, events, users, cfg):
    user = target_user(users, cfg)
    app_id, resource_id = app_ids(events, cfg["app_display_name"])
    device = attacker_device(cfg)
    t = as_time(cfg["start"])
    gap = timedelta(seconds=cfg["seconds_between_prompts"])
    session = guid(f"{cfg['incident_id']}-session")
    corr = guid(f"{cfg['incident_id']}-corr")
    out = []

    for _ in range(cfg["prompts"]):
        event = signin_event(
            user,
            cfg["app_display_name"],
            app_id,
            resource_id,
            t,
            cfg["attacker_ip"],
            cfg["attacker_country"],
            device,
            cfg["user_agent"],
            password_ok=True,
            mfa_ok=False,
            risk=90,
            risk_events=["anomalousToken", "maliciousIPAddress"],
            reason="mfa_denied",
        )
        out.append(label(event, cfg, "mfa_prompt_denied", session, corr))
        t += gap

    if cfg.get("final_success"):
        event = signin_event(
            user,
            cfg["app_display_name"],
            app_id,
            resource_id,
            t,
            cfg["attacker_ip"],
            cfg["attacker_country"],
            device,
            cfg["user_agent"],
            password_ok=True,
            mfa_ok=True,
            risk=95,
            risk_events=["anomalousToken", "maliciousIPAddress"],
        )
        out.append(label(event, cfg, "mfa_prompt_accepted", session, corr))
    return out


def impossible_travel(rng, events, users, cfg):
    user = target_user(users, cfg)
    app_id, resource_id = app_ids(events, cfg["app_display_name"])
    first = as_time(cfg["start"])
    second = first + timedelta(minutes=cfg["gap_minutes"])
    bad_device = attacker_device(cfg)
    corr = guid(f"{cfg['incident_id']}-corr")

    first_event = signin_event(
        user,
        cfg["app_display_name"],
        app_id,
        resource_id,
        first,
        cfg["first_ip"],
        cfg["first_country"],
        user["normalDevice"],
        user["normalUserAgent"],
        password_ok=True,
        mfa_ok=True,
        risk=15,
        risk_events=[],
    )
    second_event = signin_event(
        user,
        cfg["app_display_name"],
        app_id,
        resource_id,
        second,
        cfg["second_ip"],
        cfg["second_country"],
        bad_device,
        cfg["user_agent"],
        password_ok=True,
        mfa_ok=True,
        risk=95,
        risk_events=["unlikelyTravel"],
    )
    return [
        label(first_event, cfg, "first_successful_login", correlation_hint=corr),
        label(second_event, cfg, "impossible_travel_login", correlation_hint=corr),
    ]


def credential_compromise(rng, events, users, cfg):
    user = target_user(users, cfg)
    device = attacker_device(cfg)
    t = as_time(cfg["start"])
    gap = timedelta(seconds=cfg["seconds_between_events"])
    session = guid(f"{cfg['incident_id']}-session")
    corr = guid(f"{cfg['incident_id']}-corr")
    out = []

    app_id, resource_id = app_ids(events, cfg["app_display_name"])
    for _ in range(cfg["failed_attempts"]):
        event = signin_event(
            user,
            cfg["app_display_name"],
            app_id,
            resource_id,
            t,
            cfg["attacker_ip"],
            cfg["attacker_country"],
            device,
            cfg["user_agent"],
            password_ok=False,
            mfa_ok=None,
            risk=82,
            risk_events=["maliciousIPAddress"],
        )
        out.append(label(event, cfg, "password_failure", correlation_hint=corr))
        t += gap

    event = signin_event(
        user,
        cfg["app_display_name"],
        app_id,
        resource_id,
        t,
        cfg["attacker_ip"],
        cfg["attacker_country"],
        device,
        cfg["user_agent"],
        password_ok=True,
        mfa_ok=True,
        risk=92,
        risk_events=["maliciousIPAddress", "anomalousToken"],
    )
    out.append(label(event, cfg, "compromised_successful_login", session, corr))
    t += gap

    for app_name in cfg["post_login_apps"]:
        app_id, resource_id = app_ids(events, app_name)
        event = signin_event(
            user,
            app_name,
            app_id,
            resource_id,
            t,
            cfg["attacker_ip"],
            cfg["attacker_country"],
            device,
            cfg["user_agent"],
            password_ok=True,
            mfa_ok=True,
            risk=88,
            risk_events=["anomalousToken"],
        )
        out.append(label(event, cfg, "post_compromise_app_access", session, corr))
        t += gap
    return out


def rebuild_ids_and_truth(events, seed):
    events.sort(key=lambda event: event["createdDateTime"])
    truth = []
    for i, event in enumerate(events, start=1):
        labels = event.pop("_truth", None)
        event["id"] = f"evt_{i:05d}"
        event["sessionId"] = event.pop("_session_hint", f"sess_{seed}_{i:05d}")
        event["correlationId"] = event.pop("_correlation_hint", guid(f"corr-{seed}-{i:05d}"))
        truth.append(
            {
                "event_id": event["id"],
                "timestamp": event["createdDateTime"],
                "incident_id": labels["incident_id"] if labels else None,
                "scenario": labels["scenario"] if labels else "normal_background",
                "attack_stage": labels["attack_stage"] if labels else None,
                "is_attack": bool(labels),
                "true_user_id": event["userId"],
                "true_user_principal_name": event["userPrincipalName"],
                "true_device_id": event["deviceDetail"]["deviceId"],
                "true_session_id": event["sessionId"],
            }
        )
    return events, truth


def attack_names(value):
    if value == "all":
        return list(ATTACK_FILES)
    names = [name.strip() for name in value.split(",") if name.strip()]
    bad = [name for name in names if name not in ATTACK_FILES]
    if bad:
        raise SystemExit(f"Unknown attack: {bad[0]}. Choose from: {', '.join(ATTACK_FILES)}")
    return list(dict.fromkeys(names))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacks", default="all", help="all, password_spray, or comma-separated attack names")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--events-in", type=Path, default=EVENTS_IN)
    parser.add_argument("--events-out", type=Path)
    parser.add_argument("--truth-out", type=Path)
    parser.add_argument("--config-dir", type=Path, default=CONFIG_DIR)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    events = read_jsonl(args.events_in)
    users = users_from(events)
    if not users:
        raise SystemExit('Attack injection requires at least one background user.')
    injectors = {
        "password_spray": password_spray,
        "mfa_fatigue": mfa_fatigue,
        "impossible_travel": impossible_travel,
        "credential_compromise": credential_compromise,
    }

    names = attack_names(args.attacks)
    for name in names:
        cfg = read_config(name, args.config_dir)
        if cfg.get('target_user') and cfg['target_user'] not in users:
            print(f"{name}: configured target absent; using {sorted(users)[0]}")
        if name == 'password_spray' and len(users) < cfg['target_user_count']:
            print(f"password_spray: only {len(users)} observed users available for {cfg['target_user_count']} targets")
        events.extend(injectors[name](rng, events, users, cfg))

    run_name = "attacks" if names == list(ATTACK_FILES) else "_".join(names)
    events_out = args.events_out or ROOT / "data" / "generated" / f"events_seed{args.seed}_{run_name}.jsonl"
    truth_out = args.truth_out or ROOT / "data" / "ground_truth" / f"truth_seed{args.seed}_{run_name}.jsonl"
    events, truth = rebuild_ids_and_truth(events, args.seed)

    write_jsonl(events_out, events)
    write_jsonl(truth_out, truth)
    print(f"Wrote {len(events)} Entra-like sign-in events to {events_out}")
    print(f"Wrote {len(truth)} truth rows to {truth_out}")
    print(f"Injected {sum(row['is_attack'] for row in truth)} attack events")


if __name__ == "__main__":
    main()
