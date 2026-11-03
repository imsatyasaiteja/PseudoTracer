"""Run simple privacy attacks against each released IAM dataset arm."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RELEASES_DIR = ROOT / "data" / "releases"
ATTACKS_DIR = ROOT / "data" / "privacy_attacks"
CONFIG = ROOT / "configs" / "privacy_attacks.yaml"
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


def user_token(event):
    return event["user"].get("uid")


def ranked_counts(events):
    counts = Counter(user_token(event) for event in events if user_token(event))
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def frequency_attack(raw_events, release_events):
    """Match activity ranks; abstain where tied ranks do not identify one user."""
    raw_ranks = ranked_counts(raw_events)
    release_ranks = ranked_counts(release_events)
    raw_ties = Counter(count for _, count in raw_ranks)
    release_ties = Counter(count for _, count in release_ranks)
    guesses = []
    for index, (token, count) in enumerate(release_ranks[: len(raw_ranks)]):
        guessed_user, reference_count = raw_ranks[index]
        candidates = max(raw_ties[reference_count], release_ties[count])
        guesses.append(
            {
                "attack": "frequency",
                "release_entity": token,
                "guessed_user_id": guessed_user if candidates == 1 else None,
                "candidate_count": candidates,
                "release_count": count,
                "reference_count": reference_count,
            }
        )
    return guesses


def value_at(event, path, default="unknown"):
    value = event
    for part in path.split("."):
        if not isinstance(value, dict):
            return default
        value = value.get(part)
    return value if value not in {None, ""} else default


def ip_prefix(value):
    parts = str(value).split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else str(value)


def rtt_bucket(value, bucket_ms):
    if bucket_ms <= 0:
        raise ValueError("RTT bucket size must be positive")
    try:
        return int(float(value) // bucket_ms) * bucket_ms
    except (TypeError, ValueError):
        return str(value)


def signature(event, bucket_hours):
    if bucket_hours <= 0 or bucket_hours > 24:
        raise ValueError("Time bucket size must be between 0 and 24 hours")
    country = event["src_endpoint"].get("location", {}).get("country")
    app = event["service"].get("name")
    hour = (event["time"] % (24 * 60 * 60 * 1000)) // (bucket_hours * 60 * 60 * 1000)
    return country, app, hour


def composite_signature(event, bucket_hours, rtt_bucket_ms):
    """Fields that become identifying when observed together, not in isolation."""
    return signature(event, bucket_hours) + (
        value_at(event, "unmapped.entra.device_type"),
        value_at(event, "unmapped.entra.user_agent"),
        ip_prefix(value_at(event, "src_endpoint.ip")),
        rtt_bucket(value_at(event, "unmapped.entra.round_trip_time_ms"), rtt_bucket_ms),
    )


def profiles(events, make_signature):
    result = defaultdict(set)
    for event in events:
        if user_token(event):
            result[user_token(event)].add(make_signature(event))
    return result


def profile_matching_attack(raw_events, release_events, make_signature, attack):
    """Use a signature index instead of comparing every pair of user profiles."""
    users_by_signature = defaultdict(set)
    for user_id, known in profiles(raw_events, make_signature).items():
        for item in known:
            users_by_signature[item].add(user_id)
    guesses = []
    for token, observed in profiles(release_events, make_signature).items():
        scores = Counter()
        for item in observed:
            scores.update(users_by_signature.get(item, ()))
        overlap = max(scores.values(), default=0)
        candidates = [user_id for user_id, score in scores.items() if score == overlap]
        guesses.append(
            {
                "attack": attack,
                "release_entity": token,
                "guessed_user_id": candidates[0] if len(candidates) == 1 else None,
                "candidate_count": len(candidates),
                "matching_signatures": overlap,
                "observed_signatures": len(observed),
            }
        )
    return guesses


def auxiliary_knowledge_attack(raw_events, release_events, bucket_hours):
    """Match retained location, application, and time-of-day patterns to a reference set."""
    return profile_matching_attack(
        raw_events,
        release_events,
        lambda event: signature(event, bucket_hours),
        "auxiliary_knowledge",
    )


def composite_auxiliary_attack(raw_events, release_events, bucket_hours, rtt_bucket_ms):
    return profile_matching_attack(
        raw_events,
        release_events,
        lambda event: composite_signature(event, bucket_hours, rtt_bucket_ms),
        "composite_auxiliary_knowledge",
    )


def snapshots(events, split="midpoint"):
    if split != "midpoint":
        raise ValueError("Only midpoint snapshot splitting is supported")
    ordered = sorted(events, key=lambda event: event["time"])
    if not ordered:
        return [], []
    # Do not split simultaneous events across snapshots. For two distinct
    # timestamps the earlier event belongs to the first snapshot.
    cutoff = ordered[(len(ordered) - 1) // 2]["time"]
    first = [event for event in ordered if event["time"] <= cutoff]
    second = [event for event in ordered if event["time"] > cutoff]
    return first, second


def multi_snapshot_attack(events, split):
    """Link identical released user tokens seen in both halves of the dataset."""
    first, second = snapshots(events, split)
    first_by_user = defaultdict(list)
    second_by_user = defaultdict(list)
    for event in first:
        first_by_user[user_token(event)].append(event_id(event))
    for event in second:
        second_by_user[user_token(event)].append(event_id(event))

    return [
        {
            "attack": "multi_snapshot",
            "left_entity": token,
            "right_entity": token,
            "left_event_ids": first_by_user[token],
            "right_event_ids": second_by_user[token],
        }
        for token in sorted(first_by_user.keys() & second_by_user.keys())
    ]


def run_attacks(raw_events, release_events, cfg):
    """A strong baseline: identity-labelled profiles from this same dataset.

    Attacks use counts/signatures, not event IDs, the key, or ground-truth
    labels. These rates do not estimate risk with independent auxiliary data.
    """
    bucket_hours = cfg["auxiliary_knowledge"]["time_bucket_hours"]
    rtt_bucket_ms = cfg["composite_auxiliary_knowledge"]["rtt_bucket_ms"]
    return (
        frequency_attack(raw_events, release_events)
        + auxiliary_knowledge_attack(raw_events, release_events, bucket_hours)
        + composite_auxiliary_attack(raw_events, release_events, bucket_hours, rtt_bucket_ms)
        + multi_snapshot_attack(release_events, cfg["multi_snapshot"]["split"])
    )


def arm_names(value):
    allowed = {"raw", "masked", "hmac"}
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names or set(names) - allowed:
        raise SystemExit("Choose one or more of: raw, masked, hmac")
    return names


def main():
    parser = argparse.ArgumentParser(description="Run privacy attacks on released IAM data.")
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run", default=RUN_NAME)
    parser.add_argument("--releases-dir", type=Path, default=RELEASES_DIR)
    parser.add_argument("--attacks-dir", type=Path, default=ATTACKS_DIR)
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()

    cfg = load_config(args.config)
    raw_events = read_jsonl(args.releases_dir / f"raw_{args.run}.jsonl")
    for arm in arm_names(args.arms):
        events = read_jsonl(args.releases_dir / f"{arm}_{args.run}.jsonl")
        output = args.attacks_dir / f"{arm}_{args.run}_privacy_attacks.jsonl"
        rows = run_attacks(raw_events, events, cfg)
        write_jsonl(output, rows)
        print(f"Wrote {len(rows)} {arm.upper()} privacy attack attempts to {output}")


if __name__ == "__main__":
    main()
