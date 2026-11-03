"""Build a seeded IAM population from a bounded public-data sample."""

import argparse
import csv
import hashlib
import json
import random
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RBA_CSV = ROOT / "data" / "source" / "rba-dataset.csv"
if not RBA_CSV.exists():
    RBA_CSV = ROOT / "rba-dataset.csv"
EVENTS_OUT = ROOT / "data" / "generated" / "events_seed42.jsonl"
TRUTH_OUT = ROOT / "data" / "ground_truth" / "truth_seed42.jsonl"

SEED = 42
N_USERS = 20
N_DEVICES = 30
N_EVENTS = 3000


def guid(value):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"pseudotracer-{value}"))


APPS = [
    ("Finance Portal", guid("app-finance-portal")),
    ("HR Portal", guid("app-hr-portal")),
    ("Code Repository", guid("app-code-repository")),
]
MFA = ["pushNotification", "softwareOath", "sms", "fido2SecurityKey"]
CLIENT_APPS = ["Browser", "Browser", "Mobile Apps and Desktop clients"]
NAMES = [
    "Alice Tan",
    "Ben Carter",
    "Chloe Lim",
    "Daniel Wong",
    "Emma Singh",
    "Farah Khan",
    "Grace Lee",
    "Hugo Martin",
    "Iris Chen",
    "Jonas Weber",
    "Kai Nakamura",
    "Lena Ortiz",
    "Maya Patel",
    "Noah Smith",
    "Olivia Brown",
    "Priya Rao",
    "Ravi Menon",
    "Sara Novak",
    "Theo Garcia",
    "Zara Ali",
]
DEPT_ROLES = [
    ("Finance", "analyst"),
    ("Finance", "accountant"),
    ("Engineering", "developer"),
    ("Engineering", "sre"),
    ("HR", "hr_specialist"),
    ("Sales", "account_executive"),
]


def clean(value):
    value = (value or "").strip()
    return "" if value == "-" else value


def is_true(value):
    return str(value).lower() == "true"


def fallback_rba_sample():
    return [
        {
            "ip": f"203.0.113.{i}",
            "country": country,
            "device_type": "desktop",
            "browser": "Chrome",
            "os": "Windows 11",
            "user_agent": "Mozilla/5.0",
            "round_trip_time_ms": 40 + i * 10,
            "success": True,
        }
        for i, country in enumerate(["SG", "US", "AU", "GB", "DE", "IN", "JP"], start=1)
    ]


def milliseconds(value):
    try:
        return max(1, round(float(value)))
    except (ValueError, TypeError, OverflowError):
        return None


def typical_rtt(rng, device_type):
    # The public sample may omit RTT, so use one stable baseline per device.
    base = {"desktop": 45, "laptop": 50, "mobile": 110, "tablet": 85}.get(device_type.lower(), 70)
    return max(10, round(rng.gauss(base, 15)))


def load_rba_sample(csv_path=RBA_CSV, limit=10000, source_info=None):
    if source_info is not None:
        source_info.update({'source': 'synthetic_fallback', 'sampling': 'first valid non-attack rows',
                            'sample_limit': limit})
    if not csv_path.exists():
        return fallback_rba_sample()

    rows = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if is_true(row.get("Is Attack IP")) or is_true(row.get("Is Account Takeover")):
                continue

            ip = clean(row.get("IP Address"))
            country = clean(row.get("Country"))
            if not ip or not country:
                continue

            rows.append(
                {
                    "ip": ip,
                    "country": country,
                    "device_type": clean(row.get("Device Type")) or "desktop",
                    "browser": clean(row.get("Browser Name and Version")) or "unknown",
                    "os": clean(row.get("OS Name and Version")) or "unknown",
                    "user_agent": clean(row.get("User Agent String")) or "unknown",
                    "round_trip_time_ms": milliseconds(clean(row.get("Round-Trip Time [ms]"))),
                    "success": is_true(row.get("Login Successful")),
                }
            )
            if len(rows) >= limit:
                break

    if rows and source_info is not None:
        source_info['source'] = 'rba_prefix_sample'
    return rows or fallback_rba_sample()


def build_world(rng, rba_rows, n_users, n_devices):
    rows_by_country = defaultdict(list)
    for row in rba_rows:
        rows_by_country[row["country"]].append(row)

    devices = {}
    for i in range(1, n_devices + 1):
        row = rng.choice(rba_rows)
        devices[f"device_{i:02d}"] = {
            "deviceId": guid(f"device-{i:02d}"),
            "displayName": f"LAPTOP-{i:03d}",
            "operatingSystem": row["os"],
            "browser": row["browser"],
            "deviceType": row["device_type"],
            "userAgent": row["user_agent"],
            "roundTripTimeMs": row["round_trip_time_ms"] or typical_rtt(rng, row["device_type"]),
            "isManaged": True,
            "isCompliant": rng.random() < 0.92,
            "trustType": "Azure AD joined",
        }

    users = []
    countries = sorted(rows_by_country)
    for i in range(1, n_users + 1):
        name = NAMES[i - 1] if i <= len(NAMES) else f"User {i:02d}"
        country = rng.choice(countries)
        country_ips = sorted({row["ip"] for row in rows_by_country[country]})
        department, role = DEPT_ROLES[(i - 1) % len(DEPT_ROLES)]
        device_names = [f"device_{index:02d}" for index in range(i, n_devices + 1, n_users)]

        users.append(
            {
                "userId": guid(f"user-{i:02d}"),
                "userDisplayName": name,
                "userPrincipalName": name.lower().replace(" ", ".") + "@contoso.example",
                "department": department,
                "role": role,
                "mfaMethod": rng.choice(MFA),
                "normalCountry": country,
                "normalIps": rng.sample(country_ips, min(4, len(country_ips))),
                "normalHour": rng.randint(7, 11),
                "knownDevices": device_names,
                "commonApp": APPS[(i - 1) % len(APPS)],
            }
        )

    return users, devices, rows_by_country


def status(success, reason="bad_password"):
    if success:
        return {"errorCode": 0, "failureReason": "Other.", "additionalDetails": "Success"}
    if reason == "mfa_denied":
        return {
            "errorCode": 500121,
            "failureReason": "Authentication failed during strong authentication request.",
            "additionalDetails": "MFA request was denied or not completed.",
        }
    return {
        "errorCode": 50126,
        "failureReason": "Invalid username or password.",
        "additionalDetails": "The username or password is incorrect.",
    }


def risk_level(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "none"


def make_event(rng, user, devices, rows_by_country):
    normal_country = rng.random() < 0.88
    country = user["normalCountry"] if normal_country else rng.choice(list(rows_by_country))
    rba_row = rng.choice(rows_by_country[country])

    if rng.random() < 0.86:
        device_name = user["knownDevices"][0]
    elif rng.random() < 0.85:
        device_name = rng.choice(user["knownDevices"])
    else:
        device_name = rng.choice(list(devices))

    normal_device = device_name in user["knownDevices"]
    hour = round(rng.gauss(user["normalHour"], 1.5)) % 24 if rng.random() < 0.90 else rng.randrange(24)
    timestamp = datetime(2026, 1, 5) + timedelta(
        days=rng.randrange(21),
        hours=hour,
        minutes=rng.randrange(60),
        seconds=rng.randrange(60),
    )

    ip = rng.choice(user["normalIps"]) if normal_country and rng.random() < 0.82 else rba_row["ip"]
    app_name, app_id = user["commonApp"] if rng.random() < 0.65 else rng.choice(APPS)
    client_app = rng.choice(CLIENT_APPS)
    mfa_required = app_name != "Code Repository" or rng.random() < 0.65
    success_rate = 0.96 if normal_country and normal_device else 0.84
    success_rate += 0.02 if rba_row["success"] else -0.04
    success = rng.random() < success_rate

    risk = 5
    risk += 18 if not normal_country else 0
    risk += 25 if not normal_device else 0
    risk += 12 if abs(hour - user["normalHour"]) > 3 else 0
    risk += 10 if not success else 0

    return entra_signin(user, devices[device_name], app_name, app_id, timestamp, ip, country, success, risk, mfa_required, client_app)


def entra_signin(user, device, app_name, app_id, timestamp, ip, country, success, risk, mfa_required, client_app):
    level = risk_level(risk)
    auth_steps = [{"authenticationMethod": "Password", "succeeded": success}]
    if mfa_required and success:
        auth_steps.append({"authenticationMethod": user["mfaMethod"], "succeeded": True})
    risk_events = ["unfamiliarFeatures"] if risk >= 40 else []
    return {
        "id": None,
        "createdDateTime": timestamp.isoformat() + "Z",
        "userId": user["userId"],
        "userPrincipalName": user["userPrincipalName"],
        "userDisplayName": user["userDisplayName"],
        "appId": app_id,
        "appDisplayName": app_name,
        "resourceId": guid(f"resource-{app_name}"),
        "resourceDisplayName": app_name,
        "ipAddress": ip,
        "clientAppUsed": client_app,
        "correlationId": None,
        "conditionalAccessStatus": "success" if success else "notApplied",
        "isInteractive": True,
        "authenticationRequirement": "multiFactorAuthentication" if mfa_required else "singleFactorAuthentication",
        "authenticationDetails": auth_steps,
        "status": status(success),
        "deviceDetail": {
            "deviceId": device["deviceId"],
            "displayName": device["displayName"],
            "operatingSystem": device["operatingSystem"],
            "browser": device["browser"],
            "isManaged": device["isManaged"],
            "isCompliant": device["isCompliant"],
            "trustType": device["trustType"],
            "deviceType": device["deviceType"],
        },
        "location": {"city": "", "state": "", "countryOrRegion": country},
        "riskDetail": "unfamiliarFeatures" if risk_events else "none",
        "riskLevelAggregated": level,
        "riskLevelDuringSignIn": level,
        "riskState": "atRisk" if risk_events else "none",
        "riskEventTypes_v2": risk_events,
        "userAgent": device["userAgent"],
        "roundTripTimeMs": device["roundTripTimeMs"],
        "identityContext": {"department": user["department"], "role": user["role"]},
        "riskScore": min(risk, 100),
    }


def add_ids_and_truth(events, seed):
    events.sort(key=lambda event: event["createdDateTime"])
    truth = []
    for i, event in enumerate(events, start=1):
        event["id"] = f"evt_{i:05d}"
        event["sessionId"] = event.pop("_session_hint", f"sess_{seed}_{i:05d}")
        event["correlationId"] = event.pop("_correlation_hint", guid(f"corr-{seed}-{i:05d}"))
        truth.append(
            {
                "event_id": event["id"],
                "timestamp": event["createdDateTime"],
                "incident_id": None,
                "scenario": "normal_background",
                "attack_stage": None,
                "is_attack": False,
                "true_user_id": event["userId"],
                "true_user_principal_name": event["userPrincipalName"],
                "true_device_id": event["deviceDetail"]["deviceId"],
                "true_session_id": event["sessionId"],
            }
        )
    return events, truth


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Build a small Entra-like IAM dataset.")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--events", type=int, default=N_EVENTS)
    parser.add_argument("--users", type=int, default=N_USERS)
    parser.add_argument("--devices", type=int, default=N_DEVICES)
    parser.add_argument("--rba-csv", type=Path, default=RBA_CSV)
    parser.add_argument("--events-out", type=Path, default=EVENTS_OUT)
    parser.add_argument("--truth-out", type=Path, default=TRUTH_OUT)
    parser.add_argument("--source-info-out", type=Path, help="Write source provenance for this experiment.")
    args = parser.parse_args()
    if args.events < 1 or args.users < 1 or args.devices < args.users:
        raise SystemExit("Use at least 1 event and user, with devices greater than or equal to users.")

    rng = random.Random(args.seed)
    source_info = {}
    rba_rows = load_rba_sample(args.rba_csv, source_info=source_info)
    source_info['sampled_rows'] = len(rba_rows)
    source_info['sample_sha256'] = hashlib.sha256(json.dumps(rba_rows, sort_keys=True).encode()).hexdigest()
    if args.source_info_out:
        args.source_info_out.parent.mkdir(parents=True, exist_ok=True)
        args.source_info_out.write_text(json.dumps(source_info, indent=2) + '\n', encoding='utf-8')
    print(f"Source: {source_info['source']} ({len(rba_rows)} rows; not a random sample of the full RBA dataset)")
    users, devices, rows_by_country = build_world(rng, rba_rows, args.users, args.devices)
    events = [make_event(rng, rng.choice(users), devices, rows_by_country) for _ in range(args.events)]
    events, truth = add_ids_and_truth(events, args.seed)

    write_jsonl(args.events_out, events)
    write_jsonl(args.truth_out, truth)
    print(f"Wrote {len(events)} Entra-like sign-in events to {args.events_out}")
    print(f"Wrote {len(truth)} truth rows to {args.truth_out}")


if __name__ == "__main__":
    main()
