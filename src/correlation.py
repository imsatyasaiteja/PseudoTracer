"""Detect IAM incident hypotheses from a released OCSF event stream."""

import argparse
import json
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict, defaultdict, deque
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


def threshold_windows(events, minutes, min_events, min_users=1):
    """Merge overlapping qualifying windows into one incident per burst."""
    window_ms = minutes * 60 * 1000
    users = Counter()
    left = 0
    active = None
    for index, event in enumerate(events):
        users[event["user"].get("uid")] += 1
        while event["time"] - events[left]["time"] > window_ms:
            user = events[left]["user"].get("uid")
            users[user] -= 1
            if not users[user]:
                del users[user]
            left += 1
        known_users = len(users) - (None in users)
        if index - left + 1 < min_events or known_users < min_users:
            continue
        if active is not None and left > active[1]:
            start, end, detected_at = active
            yield events[start:end + 1], detected_at
            active = None
        if active is None:
            active = [left, index, event["time"]]
        else:
            active[1] = index
    if active is not None:
        start, end, detected_at = active
        yield events[start:end + 1], detected_at


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


def extend_session(sessions, base, session_id, minutes):
    """Add later events from the same session to complete an incident timeline."""
    if not session_id:
        return base
    end_time = base[-1]["time"] + minutes * 60 * 1000
    event_ids = {event_id(event) for event in base}
    group = sessions.get(session_id, [])
    start = bisect_left(group, base[0]["time"], key=lambda event: event["time"])
    end = bisect_right(group, end_time, key=lambda event: event["time"])
    extra = group[start:end]
    return sorted(base + [event for event in extra if event_id(event) not in event_ids], key=lambda event: event["time"])


def password_sprays(events, cfg):
    failures = [event for event in events if event["status_code"] == "50126"]
    incidents = []
    for ip, group in group_by(failures, lambda event: event["src_endpoint"].get("ip")).items():
        for window, detected_at in threshold_windows(group, cfg["window_minutes"], cfg["min_failures"], cfg["min_users"]):
            incidents.append(incident("password_spray", "same_ip_many_users", window, detected_at, {"source_ip": ip}))
    return incidents


def mfa_fatigue(events, cfg, sessions):
    denials = [event for event in events if event["status_code"] == "500121"]
    incidents = []
    for user_id, group in group_by(denials, lambda event: event["user"].get("uid")).items():
        for window, detected_at in threshold_windows(group, cfg["window_minutes"], cfg["min_denials"]):
            trigger = next(event for event in window if event["time"] == detected_at)
            timeline = extend_session(sessions, window, trigger["session"].get("uid"), cfg["session_extension_minutes"])
            incidents.append(incident("mfa_fatigue", "repeated_mfa_denials", timeline, detected_at, {"user_id": user_id}))
    return incidents


def impossible_travel(events, cfg):
    """Flag high-risk country changes; this is not a distance/speed calculation."""
    successes = [event for event in events if event["status_id"] == 1]
    limit_ms = cfg["window_minutes"] * 60 * 1000
    incidents = []
    for user_id, group in group_by(successes, lambda event: event["user"].get("uid")).items():
        recent = OrderedDict()
        for current in group:
            country = current["src_endpoint"].get("location", {}).get("country")
            risk = current.get("unmapped", {}).get("entra", {}).get("risk_score", 0)
            if not country:
                continue
            while recent and current["time"] - next(iter(recent.values()))["time"] > limit_ms:
                recent.popitem(last=False)
            if risk >= cfg["min_risk_score"]:
                # One latest event per country makes this search at most two steps.
                previous = next((event for other, event in reversed(recent.items()) if other != country), None)
                if previous is not None:
                    incidents.append(incident("impossible_travel", "same_user_different_country", [previous, current], current["time"], {"user_id": user_id}))
            recent.pop(country, None)
            recent[country] = current
    return incidents


def credential_compromises(events, cfg, sessions):
    incidents = []
    known = [event for event in events if event["user"].get("uid") and event["src_endpoint"].get("ip")]
    key = lambda event: (event["user"]["uid"], event["src_endpoint"]["ip"])
    limit_ms = cfg["window_minutes"] * 60 * 1000
    for (user_id, ip), group in group_by(known, key).items():
        failures = deque()
        for event in group:
            while failures and event["time"] - failures[0]["time"] > limit_ms:
                failures.popleft()
            if event["status_code"] == "50126":
                failures.append(event)
            elif event["status_id"] == 1:
                if len(failures) >= cfg["min_failures"]:
                    base = list(failures) + [event]
                    timeline = extend_session(sessions, base, event["session"].get("uid"), cfg["session_extension_minutes"])
                    incidents.append(incident("credential_compromise", "failures_then_success", timeline, event["time"], {"user_id": user_id, "source_ip": ip}))
                failures.clear()
    return incidents


def correlate(events, cfg):
    events = sorted(events, key=lambda event: event["time"])
    sessions = group_by(events, lambda event: event["session"].get("uid"))
    incidents = []
    incidents.extend(password_sprays(events, cfg["password_spray"]))
    incidents.extend(mfa_fatigue(events, cfg["mfa_fatigue"], sessions))
    incidents.extend(impossible_travel(events, cfg["impossible_travel"]))
    incidents.extend(credential_compromises(events, cfg["credential_compromise"], sessions))
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
