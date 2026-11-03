"""Score privacy attacks against truth that is unavailable to the attacker."""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from privacy_attacks import composite_signature, signature, snapshots


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
    """An absent denominator is unmeasured, not evidence of zero risk."""
    return round(top / bottom, 4) if bottom else None


def get_field(event, path):
    value = event
    for part in path.split("."):
        value = value.get(part, {}) if isinstance(value, dict) else {}
    return value if isinstance(value, str) and value else None


def direct_identifier_counts(raw_events, release_events):
    """Count disclosed and total distinct source field/value pairs.

    Check exact strings anywhere, and word-delimited identifiers in free text.
    This catches identifiers copied into messages or unmapped fields without
    scanning every known identifier against every event.
    """
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
    originals = {(path, value) for event in raw_events for path in paths if (value := get_field(event, path))}
    known_values = {value for _, value in originals}
    disclosed = set()
    # Keep email addresses, IPs and hyphenated identifiers intact. Include
    # multiword display names without matching "alice" inside a HMAC token.
    words = re.compile(r"[\w@.-]+")
    known_phrases = {tuple(words.findall(value)): value for value in known_values}
    phrase_lengths = {len(phrase) for phrase in known_phrases if phrase}

    def inspect(value):
        if isinstance(value, dict):
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)
        elif isinstance(value, str):
            if value in known_values:
                disclosed.add(value)
            parts = words.findall(value)
            for length in phrase_lengths:
                for index in range(len(parts) - length + 1):
                    match = known_phrases.get(tuple(parts[index:index + length]))
                    if match:
                        disclosed.add(match)

    for event in release_events:
        inspect(event)
    return sum(value in disclosed for _, value in originals), len(originals)


def direct_identifier_leakage(raw_events, release_events):
    return ratio(*direct_identifier_counts(raw_events, release_events))


def token_truth_map(events, truth):
    truth_by_event = {row["event_id"]: row for row in truth}
    users = defaultdict(set)
    for event in events:
        row = truth_by_event.get(event["metadata"]["uid"])
        if row:
            users[event["user"].get("uid")].add(row["true_user_id"])
    return users


def guess_counts(attempts, token_users):
    attempts = [attempt for attempt in attempts if attempt.get("guessed_user_id") is not None]
    correct = 0
    for attempt in attempts:
        actual = token_users.get(attempt["release_entity"], set())
        correct += len(actual) == 1 and attempt["guessed_user_id"] in actual
    return correct, len(attempts)


def guess_success(attempts, token_users):
    correct, total = guess_counts(attempts, token_users)
    return ratio(correct, total), total


def snapshot_linkability(attempts, events, truth, split, with_counts=False):
    truth_by_event = {row["event_id"]: row for row in truth}
    linked_users = set()
    for attempt in attempts:
        left = {truth_by_event[event_id]["true_user_id"] for event_id in attempt["left_event_ids"]}
        right = {truth_by_event[event_id]["true_user_id"] for event_id in attempt["right_event_ids"]}
        if len(left) == len(right) == 1 and left == right:
            linked_users.update(left)

    first, second = snapshots(events, split)
    first_users = {truth_by_event[event["metadata"]["uid"]]["true_user_id"] for event in first}
    second_users = {truth_by_event[event["metadata"]["uid"]]["true_user_id"] for event in second}
    eligible = first_users & second_users
    correct, total = len(linked_users & eligible), len(eligible)
    result = (ratio(correct, total), len(attempts))
    return result + (correct, total) if with_counts else result


def residual_counts(events, bucket_hours):
    counts = Counter(signature(event, bucket_hours) for event in events)
    return sum(count == 1 for count in counts.values()), len(events)


def residual_uniqueness(events, bucket_hours):
    return ratio(*residual_counts(events, bucket_hours))


def composite_risk(events, truth, bucket_hours, rtt_bucket_ms, with_counts=False):
    """Measure signatures tied to one true user after the attacker has finished."""
    truth_by_event = {row["event_id"]: row for row in truth}
    users_by_signature = defaultdict(set)
    all_users = set()
    for event in events:
        row = truth_by_event.get(event["metadata"]["uid"])
        if row:
            user_id = row["true_user_id"]
            all_users.add(user_id)
            users_by_signature[composite_signature(event, bucket_hours, rtt_bucket_ms)].add(user_id)

    unique_signatures = [users for users in users_by_signature.values() if len(users) == 1]
    unique_users = {next(iter(users)) for users in unique_signatures}
    counts = (len(unique_signatures), len(users_by_signature), len(unique_users), len(all_users))
    result = (ratio(counts[0], counts[1]), ratio(counts[2], counts[3]))
    return result + counts if with_counts else result


def score_arm(arm, raw_events, release_events, attempts, truth, cfg):
    labelled = {row["event_id"] for row in truth if row.get("true_user_id")}
    if any(event["metadata"]["uid"] not in labelled for event in release_events):
        raise ValueError("Privacy scoring needs a true user label for every released event")
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
    composite_success, composite_attempts = guess_success(guesses["composite_auxiliary_knowledge"], token_users)
    combined = guesses["frequency"] + guesses["auxiliary_knowledge"] + guesses["composite_auxiliary_knowledge"]
    reid_success, reid_attempts = guess_success(combined, token_users)
    reid_correct, _ = guess_counts(combined, token_users)
    identifiers_disclosed, identifiers_total = direct_identifier_counts(raw_events, release_events)
    linkability, snapshot_attempts, snapshot_correct, snapshot_total = snapshot_linkability(
        snapshots_only, release_events, truth, cfg["multi_snapshot"]["split"], with_counts=True)
    bucket_hours = cfg["auxiliary_knowledge"]["time_bucket_hours"]
    signature_uniqueness, unique_user_rate, signature_unique, signature_total, user_unique, user_total = composite_risk(
        release_events,
        truth,
        bucket_hours,
        cfg["composite_auxiliary_knowledge"]["rtt_bucket_ms"],
        with_counts=True,
    )
    unique_events, event_total = residual_counts(release_events, bucket_hours)
    return {
        "arm": arm,
        "direct_identifier_leakage": ratio(identifiers_disclosed, identifiers_total),
        "direct_identifiers_disclosed": identifiers_disclosed,
        "direct_identifiers_total": identifiers_total,
        "reidentification_correct": reid_correct,
        "frequency_correct": guess_counts(guesses["frequency"], token_users)[0],
        "auxiliary_correct": guess_counts(guesses["auxiliary_knowledge"], token_users)[0],
        "composite_auxiliary_correct": guess_counts(guesses["composite_auxiliary_knowledge"], token_users)[0],
        "release_entities": len(token_users),
        "snapshot_linked_users": snapshot_correct,
        "snapshot_eligible_users": snapshot_total,
        "residual_unique_events": unique_events,
        "residual_total_events": event_total,
        "composite_unique_signatures": signature_unique,
        "composite_total_signatures": signature_total,
        "composite_unique_users": user_unique,
        "composite_total_users": user_total,
        "frequency_inference_risk": frequency_success,
        "auxiliary_linkage_success": auxiliary_success,
        "composite_auxiliary_linkage_success": composite_success,
        "reidentification_success_rate": reid_success,
        "cross_snapshot_linkability": linkability,
        "residual_uniqueness": ratio(unique_events, event_total),
        "composite_signature_uniqueness": signature_uniqueness,
        "composite_unique_user_rate": unique_user_rate,
        "frequency_attempts": frequency_attempts,
        "auxiliary_attempts": auxiliary_attempts,
        "composite_auxiliary_attempts": composite_attempts,
        "snapshot_attempts": snapshot_attempts,
        "reidentification_attempts": reid_attempts,
        "frequency_coverage": ratio(frequency_attempts, len(token_users)),
        "auxiliary_coverage": ratio(auxiliary_attempts, len(token_users)),
        "composite_auxiliary_coverage": ratio(composite_attempts, len(token_users)),
        "reference_model": "same_dataset_oracle",
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
