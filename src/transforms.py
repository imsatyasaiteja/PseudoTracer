"""Create RAW, MASKED, and HMAC privacy arms from OCSF authentication events."""

import argparse
import copy
import csv
import json
from pathlib import Path
from time import perf_counter

import yaml

from key_manager import hmac_token, ipv4_token, load_or_create_key


ROOT = Path(__file__).resolve().parents[1]
EVENTS_IN = ROOT / "data" / "normalized" / "ocsf_authentication_seed42_attacks.jsonl"
POLICY_IN = ROOT / "configs" / "privacy_policy.yaml"
OUTPUT_DIR = ROOT / "data" / "releases"
KEY_PATH = ROOT / "data" / "keys" / "dataset_seed42.key"
MASKS = {
    "mask_user": "masked_user",
    "mask_email": "masked_user@masked.invalid",
    "mask_device": "masked_device",
    "mask_session": "masked_session",
    "mask_correlation": "masked_correlation",
    "mask_ip": "0.0.0.0",
    "mask_fingerprint": "masked_fingerprint",
    "redact_message": "Authentication event",
}


def read_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, sort_keys=True) + "\n")


def load_policy(path):
    with path.open(encoding="utf-8") as file:
        return yaml.safe_load(file)["fields"]


def get_field(event, path):
    value = event
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def set_field(event, path, value):
    target = event
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


def pseudonym(key, rule, value):
    domain = rule["domain"]
    if rule.get("format") == "ipv4":
        return ipv4_token(key, domain, value)
    token = hmac_token(key, domain, value)
    if rule.get("format") == "email":
        return f"{token}@pseudonymous.invalid"
    return token


def transform_event(event, arm, policy, key=None, tokens=None, owners=None):
    """Return one arm. RAW is an untouched copy; other arms apply the policy."""
    if arm not in {"raw", "masked", "hmac"}:
        raise ValueError(f"Unknown privacy arm: {arm}")
    transformed = copy.deepcopy(event)
    if arm == "raw":
        return transformed

    tokens = tokens if tokens is not None else {}
    owners = owners if owners is not None else {}
    for path, rule in policy.items():
        action = rule.get(arm, "retain")
        value = get_field(transformed, path)
        if value is None or action == "retain":
            continue
        if action == "hmac":
            if key is None:
                raise ValueError("HMAC transformation needs a dataset key")
            cache_key = rule["domain"], rule.get("format"), str(value)
            if cache_key not in tokens:
                token = pseudonym(key, rule, value)
                owner_key = rule["domain"], rule.get("format"), token
                previous = owners.setdefault(owner_key, str(value))
                if previous != str(value):
                    raise ValueError("Pseudonym collision: use opaque HMAC tokens or a different dataset key")
                tokens[cache_key] = token
            value = tokens[cache_key]
        else:
            value = MASKS[action]
        set_field(transformed, path, value)
    return transformed


def transform_dataset(events, arm, policy, key=None):
    tokens = {}
    owners = {}
    return [transform_event(event, arm, policy, key, tokens, owners) for event in events]


def write_sensitivity_manifest(path, policy):
    rows = [
        {"field": field, "class": rule["class"], "masked": rule.get("masked", "retain"), "hmac": rule.get("hmac", "retain")}
        for field, rule in policy.items()
    ]
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def arm_names(value):
    allowed = {"raw", "masked", "hmac"}
    names = [name.strip() for name in value.split(",") if name.strip()]
    unknown = set(names) - allowed
    if not names or unknown:
        raise SystemExit("Choose one or more of: raw, masked, hmac")
    return names


def main():
    parser = argparse.ArgumentParser(description="Build privacy-preserving OCSF dataset arms.")
    parser.add_argument("--events-in", type=Path, default=EVENTS_IN)
    parser.add_argument("--policy", type=Path, default=POLICY_IN)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--key", type=Path, default=KEY_PATH)
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run", help="Name used in output file names.")
    parser.add_argument("--cost-out", type=Path, help="Write per-arm transformation timing and release sizes.")
    args = parser.parse_args()

    events = read_jsonl(args.events_in)
    policy = load_policy(args.policy)
    arms = arm_names(args.arms)
    key = load_or_create_key(args.key) if "hmac" in arms else None
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_sensitivity_manifest(args.output_dir / "field_sensitivity.json", policy)

    stem = args.run or args.events_in.stem.removeprefix("ocsf_authentication_")
    costs = []
    for arm in arms:
        started = perf_counter()
        rows = transform_dataset(events, arm, policy, key)
        elapsed = perf_counter() - started
        path = args.output_dir / f"{arm}_{stem}.jsonl"
        write_jsonl(path, rows)
        costs.append({"arm": arm, "events": len(rows), "transform_seconds": round(elapsed, 6),
                      "events_per_second": round(len(rows) / elapsed, 2) if elapsed else None,
                      "release_bytes": path.stat().st_size})
        print(f"Wrote {len(rows)} {arm.upper()} events to {path}")
    if args.cost_out:
        raw_bytes = next((row["release_bytes"] for row in costs if row["arm"] == "raw"), None)
        for row in costs:
            row["storage_ratio_to_raw"] = round(row["release_bytes"] / raw_bytes, 4) if raw_bytes else None
        args.cost_out.parent.mkdir(parents=True, exist_ok=True)
        with args.cost_out.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=costs[0].keys())
            writer.writeheader()
            writer.writerows(costs)


if __name__ == "__main__":
    main()
