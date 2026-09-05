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
    counts = Counter(user_token(event) for event in events)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def frequency_attack(raw_events, release_events):
    """Guess identities by matching most-active-user ranks without a key."""
    raw_ranks = ranked_counts(raw_events)
    release_ranks = ranked_counts(release_events)
    guesses = []
    for index, (token, count) in enumerate(release_ranks[: len(raw_ranks)]):
        guessed_user, reference_count = raw_ranks[index]
        guesses.append(
            {
                "attack": "frequency",
                "release_entity": token,
                "guessed_user_id": guessed_user,
                "release_count": count,
                "reference_count": reference_count,
            }
        )
    return guesses


def signature(event, bucket_hours):
    country = event["src_endpoint"].get("location", {}).get("country")
    app = event["service"].get("name")
    hour = (event["time"] // (bucket_hours * 60 * 60 * 1000)) % 24
    return country, app, hour


def profiles(events, bucket_hours):
    result = defaultdict(set)
    for event in events:
        result[user_token(event)].add(signature(event, bucket_hours))
    return result


def auxiliary_knowledge_attack(raw_events, release_events, bucket_hours):
    """Match retained location, application, and time-of-day patterns to a reference set."""
    reference = profiles(raw_events, bucket_hours)
    guesses = []
    for token, observed in profiles(release_events, bucket_hours).items():
        candidates = sorted(
            reference,
            key=lambda user_id: (-len(observed & reference[user_id]), user_id),
        )
        guessed_user = candidates[0]
        overlap = len(observed & reference[guessed_user])
        guesses.append(
            {
                "attack": "auxiliary_knowledge",
                "release_entity": token,
                "guessed_user_id": guessed_user,
                "matching_signatures": overlap,
                "observed_signatures": len(observed),
            }
        )
    return guesses


def snapshots(events, split="midpoint"):
    if split != "midpoint":
        raise ValueError("Only midpoint snapshot splitting is supported")
    ordered = sorted(events, key=lambda event: event["time"])
    cutoff = ordered[len(ordered) // 2]["time"]
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
    bucket_hours = cfg["auxiliary_knowledge"]["time_bucket_hours"]
    return (
        frequency_attack(raw_events, release_events)
        + auxiliary_knowledge_attack(raw_events, release_events, bucket_hours)
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
