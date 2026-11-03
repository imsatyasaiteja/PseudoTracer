"""Score correlation output against the ground-truth sidecar."""

import argparse
import csv
import json
from collections import Counter, defaultdict
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


def entity_link_counts(incidents, truth):
    """Count matching user pairs without materializing every pair."""
    truth_by_event = {row["event_id"]: row for row in truth}
    correct = total = 0
    for incident in incidents:
        if "user_id" not in incident["entities"]:
            continue
        users = Counter(truth_by_event[event_id]["true_user_id"] for event_id in set(incident["event_ids"]) if event_id in truth_by_event)
        count = sum(users.values())
        total += count * (count - 1) // 2
        correct += sum(count * (count - 1) // 2 for count in users.values())
    return correct, total


def entity_link_accuracy(incidents, truth):
    correct, total = entity_link_counts(incidents, truth)
    return ratio(correct, total) if total else None


def timeline_and_detection(incidents, truth, with_counts=False):
    by_incident = defaultdict(list)
    for row in truth:
        if row["is_attack"]:
            by_incident[row["incident_id"]].append(row)

    by_event = defaultdict(list)
    for item in incidents:
        for event_id in set(item["event_ids"]):
            by_event[item["scenario"], event_id].append(item["detected_at"])

    completeness = []
    delays = []
    detected = 0
    covered_events = total_events = 0
    for rows in by_incident.values():
        covered = 0
        detections = []
        for row in rows:
            matches = by_event[row["scenario"], row["event_id"]]
            covered += bool(matches)
            # A later session extension cannot make an earlier alert detect an attack.
            detections.extend(time for time in matches if time >= timestamp_ms(row["timestamp"]))
        completeness.append(covered / len(rows))
        covered_events += covered
        total_events += len(rows)
        if detections:
            detected += 1
            first_truth = min(timestamp_ms(row["timestamp"]) for row in rows)
            delays.append((min(detections) - first_truth) / 1000)
    coverage = ratio(sum(completeness), len(completeness)) if completeness else None
    result = (coverage, round(sum(delays) / len(delays), 2) if delays else None, detected)
    return result + (covered_events, total_events) if with_counts else result


def score(arm, incidents, truth, scenario="all"):
    """Score unique flagged events; 'all' measures attack versus background.

    Scenario rows require the correct rule. Empty denominators are left blank.
    """
    attack_truth = [row for row in truth if row["is_attack"] and (scenario == "all" or row["scenario"] == scenario)]
    selected = [item for item in incidents if scenario == "all" or item["scenario"] == scenario]
    actual = {row["event_id"] for row in attack_truth}
    predicted = event_ids(selected)
    true_positive = len(actual & predicted)
    false_positive = len(predicted - actual)
    false_negative = len(actual - predicted)
    negatives = len({row["event_id"] for row in truth} - actual)
    actual_incidents = len({row["incident_id"] for row in attack_truth})
    completeness, delay, detected, covered, timeline_total = timeline_and_detection(selected, attack_truth, with_counts=True)
    linked_correct, linked_total = entity_link_counts(selected, truth)
    link_accuracy = ratio(linked_correct, linked_total) if linked_total else None
    return {
        "arm": arm,
        "scenario": scenario,
        "predicted_incidents": len(selected),
        "attack_events": len(actual),
        "predicted_events": len(predicted),
        "true_positive_events": true_positive,
        "false_positive_events": false_positive,
        "false_negative_events": false_negative,
        "normal_events": negatives,
        "entity_link_correct_pairs": linked_correct,
        "entity_link_total_pairs": linked_total,
        "timeline_covered_events": covered,
        "timeline_total_events": timeline_total,
        "precision": ratio(true_positive, len(predicted)) if predicted else "",
        "recall": ratio(true_positive, len(actual)) if actual else "",
        "f1": ratio(2 * true_positive, len(predicted) + len(actual)) if predicted or actual else "",
        "false_positive_rate": ratio(false_positive, negatives) if negatives else "",
        "entity_link_accuracy": link_accuracy if link_accuracy is not None else "",
        "timeline_completeness": completeness if completeness is not None else "",
        "mean_time_to_detect_seconds": delay if delay is not None else "",
        "incidents_detected": detected,
        "actual_incidents": actual_incidents,
        "incident_recall": ratio(detected, actual_incidents) if actual_incidents else "",
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
