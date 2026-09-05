"""Score privacy attacks against truth that is unavailable to the attacker."""

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from privacy_attacks import signature, snapshots


ROOT = Path(__file__).resolve().parents[1]
RELEASES_DIR = ROOT / "data" / "releases"
ATTACKS_DIR = ROOT / "data" / "privacy_attacks"
TRUTH_IN = ROOT / "data" / "ground_truth" / "truth_seed42_attacks.jsonl"
CONFIG = ROOT / "configs" / "privacy_attacks.yaml"
RESULTS_OUT = ROOT / "results" / "privacy_seed42_attacks.csv"
RUN_NAME = "seed42_attacks"


def read_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def load_config(path):
    with path.open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def ratio(top, bottom):
    return round(top / bottom, 4) if bottom else 0.0


def get_field(event, path):
    value = event
    for part in path.split("."):
        value = value.get(part, {}) if isinstance(value, dict) else {}
    return value if isinstance(value, str) and value else None


def direct_identifier_leakage(raw_events, release_events):
    paths = [
        "user.uid",
        "user.name",
        "user.email_addr",
        "user.display_name",
        "src_endpoint.uid",
        "src_endpoint.name",
        "src_endpoint.ip",
        "session.uid",
        "metadata.correlation_uid",
    ]
    leaked = total = 0
    for path in paths:
        raw_values = {get_field(event, path) for event in raw_events if get_field(event, path)}
        release_values = {get_field(event, path) for event in release_events if get_field(event, path)}
        leaked += len(raw_values & release_values)
        total += len(raw_values)
    return ratio(leaked, total)


def token_truth_map(events, truth):
    truth_by_event = {row["event_id"]: row for row in truth}
    users = defaultdict(set)
    for event in events:
        row = truth_by_event.get(event["metadata"]["uid"])
        if row:
            users[event["user"].get("uid")].add(row["true_user_id"])
    return users


def guess_success(attempts, token_users):
    correct = 0
    for attempt in attempts:
        actual = token_users.get(attempt["release_entity"], set())
        correct += len(actual) == 1 and attempt["guessed_user_id"] in actual
    return ratio(correct, len(attempts)), len(attempts)


def snapshot_linkability(attempts, events, truth, split):
    truth_by_event = {row["event_id"]: row for row in truth}
    correct = 0
    for attempt in attempts:
        left = {truth_by_event[event_id]["true_user_id"] for event_id in attempt["left_event_ids"]}
        right = {truth_by_event[event_id]["true_user_id"] for event_id in attempt["right_event_ids"]}
        correct += len(left) == len(right) == 1 and left == right

    first, second = snapshots(events, split)
    first_users = {truth_by_event[event["metadata"]["uid"]]["true_user_id"] for event in first}
    second_users = {truth_by_event[event["metadata"]["uid"]]["true_user_id"] for event in second}
    return ratio(correct, len(first_users & second_users)), len(attempts)


def residual_uniqueness(events, bucket_hours):
    counts = Counter(signature(event, bucket_hours) for event in events)
    return ratio(sum(counts[signature(event, bucket_hours)] == 1 for event in events), len(events))


def score_arm(arm, raw_events, release_events, attempts, truth, cfg):
    guesses = defaultdict(list)
    snapshots_only = []
    for attempt in attempts:
        if attempt["attack"] == "multi_snapshot":
            snapshots_only.append(attempt)
        else:
            guesses[attempt["attack"]].append(attempt)

    token_users = token_truth_map(release_events, truth)
    frequency_success, frequency_attempts = guess_success(guesses["frequency"], token_users)
    auxiliary_success, auxiliary_attempts = guess_success(guesses["auxiliary_knowledge"], token_users)
    combined = guesses["frequency"] + guesses["auxiliary_knowledge"]
    reid_success, reid_attempts = guess_success(combined, token_users)
    linkability, snapshot_attempts = snapshot_linkability(snapshots_only, release_events, truth, cfg["multi_snapshot"]["split"])
    return {
        "arm": arm,
        "direct_identifier_leakage": direct_identifier_leakage(raw_events, release_events),
        "frequency_inference_risk": frequency_success,
        "auxiliary_linkage_success": auxiliary_success,
        "reidentification_success_rate": reid_success,
        "cross_snapshot_linkability": linkability,
        "residual_uniqueness": residual_uniqueness(release_events, cfg["auxiliary_knowledge"]["time_bucket_hours"]),
        "frequency_attempts": frequency_attempts,
        "auxiliary_attempts": auxiliary_attempts,
        "snapshot_attempts": snapshot_attempts,
        "reidentification_attempts": reid_attempts,
    }


def arm_names(value):
    allowed = {"raw", "masked", "hmac"}
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names or set(names) - allowed:
        raise SystemExit("Choose one or more of: raw, masked, hmac")
    return names


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Score privacy attacks against released IAM data.")
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run", default=RUN_NAME)
    parser.add_argument("--releases-dir", type=Path, default=RELEASES_DIR)
    parser.add_argument("--attacks-dir", type=Path, default=ATTACKS_DIR)
    parser.add_argument("--truth", type=Path, default=TRUTH_IN)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--out", type=Path, default=RESULTS_OUT)
    args = parser.parse_args()

    cfg = load_config(args.config)
    raw_events = read_jsonl(args.releases_dir / f"raw_{args.run}.jsonl")
    truth = read_jsonl(args.truth)
    rows = []
    for arm in arm_names(args.arms):
        events = read_jsonl(args.releases_dir / f"{arm}_{args.run}.jsonl")
        attempts = read_jsonl(args.attacks_dir / f"{arm}_{args.run}_privacy_attacks.jsonl")
        rows.append(score_arm(arm, raw_events, events, attempts, truth, cfg))
    write_csv(args.out, rows)
    print(f"Wrote {len(rows)} privacy metric rows to {args.out}")


if __name__ == "__main__":
    main()
