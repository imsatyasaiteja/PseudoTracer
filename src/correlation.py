"""Detect IAM incident hypotheses from a released OCSF event stream."""

import argparse
import json
from collections import defaultdict
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RELEASES_DIR = ROOT / "data" / "releases"
INCIDENTS_DIR = ROOT / "data" / "correlated"
CONFIG = ROOT / "configs" / "correlation.yaml"
RUN_NAME = "seed42_attacks"


def read_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, sort_keys=True) + "\n")


def load_config(path):
    with path.open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def event_id(event):
    return event["metadata"]["uid"]


def group_by(events, key):
    groups = defaultdict(list)
    for event in events:
        value = key(event)
        if value is not None:
            groups[value].append(event)
    return groups


def time_windows(events, minutes):
    """Split a sorted group whenever it extends past the rule's time window."""
    window_ms = minutes * 60 * 1000
    start = 0
    for index, event in enumerate(events):
        if event["time"] - events[start]["time"] > window_ms:
            yield events[start:index]
            start = index
    if events:
        yield events[start:]


def incident(scenario, rule, events, detected_at, entities):
    return {
        "scenario": scenario,
        "rule": rule,
        "start_time": events[0]["time"],
        "end_time": events[-1]["time"],
        "detected_at": detected_at,
        "event_ids": [event_id(event) for event in events],
        "entities": entities,
    }


def extend_session(events, base, session_id, minutes):
    """Add later events from the same session to complete an incident timeline."""
    if not session_id:
        return base
    end_time = base[-1]["time"] + minutes * 60 * 1000
    event_ids = {event_id(event) for event in base}
    extra = [
        event
        for event in events
        if event["session"].get("uid") == session_id and base[0]["time"] <= event["time"] <= end_time
    ]
    return sorted(base + [event for event in extra if event_id(event) not in event_ids], key=lambda event: event["time"])


def password_sprays(events, cfg):
    failures = [event for event in events if event["status_id"] == 2]
    incidents = []
    for ip, group in group_by(failures, lambda event: event["src_endpoint"].get("ip")).items():
        for window in time_windows(group, cfg["window_minutes"]):
            users = set()
            for index, event in enumerate(window, start=1):
                users.add(event["user"].get("uid"))
                if index >= cfg["min_failures"] and len(users) >= cfg["min_users"]:
                    incidents.append(incident("password_spray", "same_ip_many_users", window, event["time"], {"source_ip": ip}))
                    break
    return incidents


def mfa_fatigue(events, cfg):
    denials = [event for event in events if event["status_code"] == "500121"]
    incidents = []
    for user_id, group in group_by(denials, lambda event: event["user"].get("uid")).items():
        for window in time_windows(group, cfg["window_minutes"]):
            if len(window) >= cfg["min_denials"]:
                trigger = window[cfg["min_denials"] - 1]
                timeline = extend_session(events, window, trigger["session"].get("uid"), cfg["session_extension_minutes"])
                incidents.append(incident("mfa_fatigue", "repeated_mfa_denials", timeline, trigger["time"], {"user_id": user_id}))
    return incidents


def impossible_travel(events, cfg):
    successes = [event for event in events if event["status_id"] == 1]
    limit_ms = cfg["window_minutes"] * 60 * 1000
    incidents = []
    for user_id, group in group_by(successes, lambda event: event["user"].get("uid")).items():
        for index, current in enumerate(group):
            country = current["src_endpoint"].get("location", {}).get("country")
            risk = current.get("unmapped", {}).get("entra", {}).get("risk_score", 0)
            correlation_id = current["metadata"].get("correlation_uid")
            if not correlation_id or risk < cfg["min_risk_score"]:
                continue
            for previous in reversed(group[:index]):
                if current["time"] - previous["time"] > limit_ms:
                    break
                previous_country = previous["src_endpoint"].get("location", {}).get("country")
                if country and previous_country and country != previous_country and previous["metadata"].get("correlation_uid") == correlation_id:
                    incidents.append(incident("impossible_travel", "same_user_transaction_different_country", [previous, current], current["time"], {"user_id": user_id}))
                    break
    return incidents


def credential_compromises(events, cfg):
    incidents = []
    key = lambda event: (event["user"].get("uid"), event["src_endpoint"].get("ip"))
    limit_ms = cfg["window_minutes"] * 60 * 1000
    for (user_id, ip), group in group_by(events, key).items():
        failures = []
        for event in group:
            if event["status_code"] == "50126":
                failures.append(event)
            elif event["status_id"] == 1:
                failures = [failure for failure in failures if event["time"] - failure["time"] <= limit_ms]
                if len(failures) >= cfg["min_failures"]:
                    base = failures + [event]
                    timeline = extend_session(events, base, event["session"].get("uid"), cfg["session_extension_minutes"])
                    incidents.append(incident("credential_compromise", "failures_then_success", timeline, event["time"], {"user_id": user_id, "source_ip": ip}))
                    failures = []
    return incidents


def correlate(events, cfg):
    events = sorted(events, key=lambda event: event["time"])
    incidents = []
    incidents.extend(password_sprays(events, cfg["password_spray"]))
    incidents.extend(mfa_fatigue(events, cfg["mfa_fatigue"]))
    incidents.extend(impossible_travel(events, cfg["impossible_travel"]))
    incidents.extend(credential_compromises(events, cfg["credential_compromise"]))
    incidents.sort(key=lambda item: (item["detected_at"], item["scenario"]))
    for index, item in enumerate(incidents, start=1):
        item["incident_id"] = f"det_{index:04d}"
    return incidents


def arm_names(value):
    allowed = {"raw", "masked", "hmac"}
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names or set(names) - allowed:
        raise SystemExit("Choose one or more of: raw, masked, hmac")
    return names


def main():
    parser = argparse.ArgumentParser(description="Correlate OCSF events into IAM incident hypotheses.")
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run", default=RUN_NAME)
    parser.add_argument("--releases-dir", type=Path, default=RELEASES_DIR)
    parser.add_argument("--incidents-dir", type=Path, default=INCIDENTS_DIR)
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()

    cfg = load_config(args.config)
    for arm in arm_names(args.arms):
        source = args.releases_dir / f"{arm}_{args.run}.jsonl"
        output = args.incidents_dir / f"{arm}_{args.run}_incidents.jsonl"
        incidents = correlate(read_jsonl(source), cfg)
        write_jsonl(output, incidents)
        print(f"Wrote {len(incidents)} {arm.upper()} incident hypotheses to {output}")


if __name__ == "__main__":
    main()
