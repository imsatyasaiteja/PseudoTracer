"""Run controlled multi-seed experiments and summarize their measured results."""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from experiment_cli import ROOT, run_experiment, safe_run_id


def read_csv(path):
    with path.open(encoding='utf-8') as file:
        return list(csv.DictReader(file))


def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(records):
    """Report sample SD, not a confidence interval or a guarantee of generality."""
    groups = defaultdict(list)
    for row in records:
        groups[(row['experiment'], row['arm'], row['scenario'], row['metric'])].append(row['value'])
    result = []
    for (experiment, arm, scenario, metric), values in sorted(groups.items()):
        result.append(dict(experiment=experiment, arm=arm, scenario=scenario, metric=metric,
                           n=len(values), mean=statistics.mean(values),
                           std=statistics.stdev(values) if len(values) > 1 else ''))
    return result


def paired_deltas(records):
    references = {(r['run_id'], r['scenario'], r['metric']): r['value']
                  for r in records if r['arm'] == 'raw'}
    result = []
    for row in records:
        key = (row['run_id'], row['scenario'], row['metric'])
        if row['arm'] != 'raw' and key in references:
            result.append({**row, 'value': row['value'] - references[key]})
    return result


def metric_records(run_id, seed, experiment, family, rows):
    records = []
    for row in rows:
        for metric, value in row.items():
            if metric in {'arm', 'scenario'} or value == '':
                continue
            try:
                number = float(value)
            except (TypeError, ValueError):
                continue
            records.append(dict(run_id=run_id, seed=seed, experiment=experiment,
                                arm=row['arm'], scenario=row.get('scenario', 'all'),
                                metric=f'{family}.{metric}', value=number))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=int, default=3000)
    parser.add_argument('--users', type=int, default=20)
    parser.add_argument('--devices', type=int, default=30)
    parser.add_argument('--arms', default='raw,masked,hmac')
    parser.add_argument('--key', type=Path, help='Optional private key shared across runs.')
    parser.add_argument('--rba-csv', type=Path, default=ROOT / 'data/source/rba-dataset.csv')
    parser.add_argument('--config-dir', type=Path, default=ROOT / 'configs')
    parser.add_argument('--seeds', default='7,42,101', help='Independent background seeds (no duplicates).')
    parser.add_argument('--experiments', default='none,all',
                        help='Comma-separated selections: none, all, or individual attack names.')
    parser.add_argument('--study-id', help='New directory name under data/studies/.')
    args = parser.parse_args()
    seeds = list(dict.fromkeys(int(value) for value in args.seeds.split(',')))
    experiments = list(dict.fromkeys(args.experiments.split(',')))
    allowed = {'none', 'all', 'password_spray', 'mfa_fatigue', 'impossible_travel', 'credential_compromise'}
    if not seeds or not experiments or set(experiments) - allowed:
        parser.error('Choose at least one seed and valid experiment selection.')
    study_id = safe_run_id(args.study_id or datetime.now().strftime('study_%Y%m%d_%H%M%S'))
    destination = ROOT / 'data' / 'studies' / study_id
    destination.mkdir(parents=True, exist_ok=False)
    records, runs, costs = [], [], []
    for experiment in experiments:
        for seed in seeds:
            settings = argparse.Namespace(**vars(args))
            settings.seed, settings.attacks = seed, experiment
            settings.run_id = f'{study_id}_{experiment}_seed{seed}'
            directory = run_experiment(settings)
            runs.append(dict(run_id=directory.name, seed=seed, experiment=experiment))
            for family in ['utility', 'privacy']:
                records.extend(metric_records(directory.name, seed, experiment, family,
                                              read_csv(directory / 'results' / f'{family}.csv')))
            costs.extend({**runs[-1], **row} for row in read_csv(directory / 'results' / 'cost.csv'))
            # Save after each completed run so an interrupted study remains useful.
            write_csv(destination / 'runs.csv', runs)
            write_csv(destination / 'measurements.csv', records)
            write_csv(destination / 'summary.csv', summarize(records))
            write_csv(destination / 'paired_deltas.csv', paired_deltas(records))
            write_csv(destination / 'cost.csv', costs)
    (destination / 'study.json').write_text(json.dumps({
        'seeds': seeds, 'experiments': experiments, 'events': args.events,
        'users': args.users, 'devices': args.devices, 'arms': args.arms,
        'paired_delta': 'arm minus RAW within the same run; direction depends on the metric',
        'spread': 'Sample standard deviation across seeds; blank for a single observation',
    }, indent=2) + '\n', encoding='utf-8')
    print(f'\nStudy results: {destination}')


if __name__ == '__main__':
    main()
