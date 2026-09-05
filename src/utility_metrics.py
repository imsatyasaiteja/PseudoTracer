"""Score correlation output against the ground-truth sidecar."""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRUTH_IN = ROOT / "data" / "ground_truth" / "truth_seed42_attacks.jsonl"
INCIDENTS_DIR = ROOT / "data" / "correlated"
RESULTS_OUT = ROOT / "results" / "utility_seed42_attacks.csv"
RUN_NAME = "seed42_attacks"


def read_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def timestamp_ms(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def ratio(top, bottom):
    return round(top / bottom, 4) if bottom else 0.0


def event_ids(incidents):
    return {event_id for incident in incidents for event_id in incident["event_ids"]}


def entity_link_accuracy(incidents, truth):
    truth_by_event = {row["event_id"]: row for row in truth}
    correct = total = 0
    for incident in incidents:
        if "user_id" not in incident["entities"]:
            continue
        users = [truth_by_event[event_id]["true_user_id"] for event_id in incident["event_ids"] if event_id in truth_by_event]
        for index, user_id in enumerate(users):
            for other in users[index + 1 :]:
                total += 1
                correct += user_id == other
    return ratio(correct, total) if total else None


def timeline_and_detection(incidents, truth):
    by_incident = defaultdict(list)
    for row in truth:
        if row["is_attack"]:
            by_incident[row["incident_id"]].append(row)

    completeness = []
    delays = []
    detected = 0
    for rows in by_incident.values():
        scenario = rows[0]["scenario"]
        truth_ids = {row["event_id"] for row in rows}
        matches = [item for item in incidents if item["scenario"] == scenario and truth_ids.intersection(item["event_ids"])]
        covered = set().union(*(set(item["event_ids"]) for item in matches)) if matches else set()
        completeness.append(ratio(len(truth_ids & covered), len(truth_ids)))
        if matches:
            detected += 1
            first_truth = min(timestamp_ms(row["timestamp"]) for row in rows)
            delays.append(max(0, min(item["detected_at"] for item in matches) - first_truth) / 1000)
    return ratio(sum(completeness), len(completeness)), round(sum(delays) / len(delays), 2) if delays else None, detected


def score(arm, incidents, truth, scenario="all"):
    attack_truth = [row for row in truth if row["is_attack"] and (scenario == "all" or row["scenario"] == scenario)]
    selected = [item for item in incidents if scenario == "all" or item["scenario"] == scenario]
    actual = {row["event_id"] for row in attack_truth}
    predicted = event_ids(selected)
    true_positive = len(actual & predicted)
    precision = ratio(true_positive, len(predicted))
    recall = ratio(true_positive, len(actual))
    f1 = ratio(2 * precision * recall, precision + recall)
    completeness, delay, detected = timeline_and_detection(selected, attack_truth)
    link_accuracy = entity_link_accuracy(selected, truth)
    return {
        "arm": arm,
        "scenario": scenario,
        "predicted_incidents": len(selected),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "entity_link_accuracy": link_accuracy if link_accuracy is not None else "",
        "timeline_completeness": completeness,
        "mean_time_to_detect_seconds": delay if delay is not None else "",
        "incidents_detected": detected,
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
    parser = argparse.ArgumentParser(description="Calculate utility metrics from correlated incidents.")
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run", default=RUN_NAME)
    parser.add_argument("--truth", type=Path, default=TRUTH_IN)
    parser.add_argument("--incidents-dir", type=Path, default=INCIDENTS_DIR)
    parser.add_argument("--out", type=Path, default=RESULTS_OUT)
    args = parser.parse_args()

    truth = read_jsonl(args.truth)
    scenarios = sorted({row["scenario"] for row in truth if row["is_attack"]})
    rows = []
    for arm in arm_names(args.arms):
        incidents = read_jsonl(args.incidents_dir / f"{arm}_{args.run}_incidents.jsonl")
        rows.append(score(arm, incidents, truth))
        rows.extend(score(arm, incidents, truth, scenario) for scenario in scenarios)
    write_csv(args.out, rows)
    print(f"Wrote {len(rows)} utility rows to {args.out}")


if __name__ == "__main__":
    main()
