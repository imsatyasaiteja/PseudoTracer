"""Local-only dashboard adapter. Runs the existing CLI without modifying it."""
import csv
import base64
import json
import re
import subprocess
import sys
import threading
from functools import lru_cache
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import yaml
from event_query import event_page
from incident_view import incident_page

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from privacy_metrics import direct_identifier_counts, guess_counts, token_truth_map, read_jsonl, score_arm
from utility_metrics import score as score_utility
RUNS = ROOT / 'data' / 'runs'
ARMS = {'raw', 'masked', 'hmac'}
ATTACKS = {'password_spray', 'mfa_fatigue', 'impossible_travel', 'credential_compromise'}
jobs = {}
lock = threading.Lock()


def new_run_id(seed, events):
    """Use the CLI's naming format; callers hold the jobs lock."""
    base = f"seed{seed}_events{events}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    name = base
    number = 2
    while name in jobs or (RUNS / name).exists():
        name = f'{base}_{number}'
        number += 1
    return name


def run_path(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
        raise ValueError('Invalid run ID')
    path = RUNS / name
    if path.is_symlink() or path.resolve().parent != RUNS.resolve():
        raise ValueError('Invalid run path')
    return path


def rows(path):
    if not path.exists():
        return []
    with path.open(encoding='utf-8') as file:
        return list(csv.DictReader(file))


@lru_cache(maxsize=64)
def saved_privacy_counts(files):
    """Recover exact counts for older runs; invalidate when any artifact changes."""
    raw, released, truth, attempts = [read_jsonl(Path(name)) for name, _, _ in files]
    labelled = {row['event_id'] for row in truth if row.get('true_user_id')}
    if any(event['metadata']['uid'] not in labelled for event in released):
        raise ValueError('Exact privacy counts require complete truth labels')
    disclosed, total = direct_identifier_counts(raw, released)
    identity_attempts = [item for item in attempts if item.get('attack') in {
        'frequency', 'auxiliary_knowledge', 'composite_auxiliary_knowledge'}]
    correct, guesses = guess_counts(identity_attempts, token_truth_map(released, truth))
    return {'direct_identifiers_disclosed': disclosed, 'direct_identifiers_total': total,
            'reidentification_correct': correct, 'reidentification_attempts': guesses}


def with_privacy_counts(path, row):
    fields = ('direct_identifiers_disclosed', 'direct_identifiers_total', 'reidentification_correct',
              'frequency_correct', 'auxiliary_correct', 'composite_auxiliary_correct', 'release_entities',
              'snapshot_linked_users', 'snapshot_eligible_users', 'residual_unique_events',
              'residual_total_events', 'composite_unique_signatures', 'composite_total_signatures',
              'composite_unique_users', 'composite_total_users')
    if all(row.get(field) not in (None, '') for field in fields):
        return row
    arm = row.get('arm')
    if arm not in ARMS:
        return row
    sources = [path / 'releases' / f'raw_{path.name}.jsonl',
               path / 'releases' / f'{arm}_{path.name}.jsonl',
               path / 'ground_truth' / 'truth.jsonl',
               path / 'privacy_attacks' / f'{arm}_{path.name}_privacy_attacks.jsonl']
    try:
        files = tuple((str(source), source.stat().st_mtime_ns, source.stat().st_size) for source in sources)
        snapshot = path / 'configs' / 'privacy_attacks.yaml'
        if snapshot.exists():
            config_file = (str(snapshot), snapshot.stat().st_mtime_ns, snapshot.stat().st_size)
            recovered = saved_metric_details('privacy', arm, 'all', files + (config_file,))
            return {**recovered, **row, **{key: recovered[key] for key in fields}}
        return {**row, **saved_privacy_counts(files)}
    except (OSError, ValueError, KeyError, TypeError):
        # Incomplete or unavailable artifacts must never become fabricated counts.
        return row


@lru_cache(maxsize=128)
def saved_metric_details(kind, arm, scenario, files):
    """Recompute missing supporting counts from immutable run artifacts, not rounded rates."""
    paths = [Path(name) for name, _, _ in files]
    if kind == 'privacy':
        raw, released, truth, attempts = [read_jsonl(path) for path in paths[:4]]
        config = yaml.safe_load(paths[4].read_text(encoding='utf-8'))
        return score_arm(arm, raw, released, attempts, truth, config)
    incidents, truth = [read_jsonl(path) for path in paths]
    return score_utility(arm, incidents, truth, scenario)


def with_utility_counts(path, row):
    fields = ('normal_events', 'entity_link_correct_pairs', 'entity_link_total_pairs',
              'timeline_covered_events', 'timeline_total_events')
    if all(row.get(key) not in (None, '') for key in fields) or row.get('arm') not in ARMS:
        return row
    sources = [path / 'correlated' / f"{row['arm']}_{path.name}_incidents.jsonl",
               path / 'ground_truth' / 'truth.jsonl']
    try:
        files = tuple((str(source), source.stat().st_mtime_ns, source.stat().st_size) for source in sources)
        recovered = saved_metric_details('utility', row['arm'], row.get('scenario', 'all'), files)
        return {**row, **{key: recovered[key] for key in fields}}
    except (OSError, ValueError, KeyError, TypeError):
        return row


def analysis_settings(path):
    """Only expose numeric detector/injector settings needed for comparisons."""
    def snapshot(name):
        source = path / 'configs' / name
        if not source.exists():
            return {}
        try:
            data = yaml.safe_load(source.read_text(encoding='utf-8'))
            return data if isinstance(data, dict) else {}
        except (OSError, yaml.YAMLError):
            return {}

    rules = snapshot('correlation.yaml')
    rule_fields = {'password_spray': ['min_users'], 'mfa_fatigue': ['min_denials'],
                   'credential_compromise': ['min_failures'], 'impossible_travel': ['window_minutes']}
    output = {'rules': {}, 'intensity': {}}
    for scenario, fields in rule_fields.items():
        output['rules'][scenario] = {field: value for field in fields
            if type(value := (rules.get(scenario) or {}).get(field)) in (int, float)}
    for scenario, fields in {'password_spray': ['target_user_count', 'spray_rounds'],
                            'mfa_fatigue': ['prompts'], 'credential_compromise': ['failed_attempts'],
                            'impossible_travel': ['gap_minutes']}.items():
        config = snapshot(f'attacks/{scenario}.yaml')
        output['intensity'][scenario] = {field: value for field in fields
            if type(value := config.get(field)) in (int, float)}
    return output


def detail(path):
    config = json.loads((path / 'config.json').read_text(encoding='utf-8'))
    config = {k: v for k, v in config.items() if k not in {'key_path', 'rba_csv'}}
    utility = rows(path / 'results' / 'utility.csv')
    privacy = rows(path / 'results' / 'privacy.csv')
    state_path = path / 'status.json'
    state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    source_path = path / 'data_source.json'
    data_source = json.loads(source_path.read_text(encoding='utf-8')) if source_path.exists() else {}
    expected = set(config.get('arms', '').split(',')) - {''}
    utility_arms = {row.get('arm') for row in utility if row.get('scenario', 'all') == 'all'}
    privacy_arms = {row.get('arm') for row in privacy}
    complete = bool(utility and privacy) and expected <= utility_arms & privacy_arms
    with lock:
        job = dict(jobs.get(path.name, {}))
        job['output'] = list(job.get('output', []))
    status = job.get('status', state.get('status', 'complete' if complete else 'incomplete'))
    if status == 'complete' and not complete:
        status = 'incomplete'
    if status == 'complete':
        privacy = [with_privacy_counts(path, row) for row in privacy]
        utility = [with_utility_counts(path, row) for row in utility]
    return {'id': path.name, 'config': config, 'utility': utility, 'privacy': privacy,
            'data_source': data_source, 'analysis_settings': analysis_settings(path),
            'cost': rows(path / 'results' / 'cost.csv'),
            'transformation_cost': rows(path / 'results' / 'transformation_cost.csv'),
            'status': status,
            'stage': state.get('stage'), 'error': state.get('error'),
            'output': job['output']}


def policy(path=None):
    snapshot = path / 'configs' / 'privacy_policy.yaml' if path else None
    use_snapshot = snapshot is not None and snapshot.exists()
    source = snapshot if use_snapshot else ROOT / 'configs' / 'privacy_policy.yaml'
    return {**yaml.safe_load(source.read_text(encoding='utf-8')),
            'source': 'snapshot' if use_snapshot else 'current'}


def validate(data):
    for name, maximum in [('events', 100000), ('users', 1000), ('devices', 2000), ('seed', 2147483647)]:
        value = data.get(name)
        if type(value) is not int or not (0 if name == 'seed' else 1) <= value <= maximum:
            raise ValueError(f'Invalid {name}; maximum {maximum}')
    if data['devices'] < data['users']:
        raise ValueError('Devices must be at least the number of users.')
    for key, allowed in [('arms', ARMS), ('attacks', ATTACKS)]:
        if not isinstance(data.get(key), list) or any(not isinstance(x, str) or x not in allowed for x in data[key]):
            raise ValueError(f'Invalid {key}')
    if not data['arms']:
        raise ValueError('Select at least one privacy arm.')


def execute(name, data):
    command = [sys.executable, '-u', str(ROOT / 'src' / 'experiment_cli.py'), 'run', '--run-id', name]
    for key in ['seed', 'events', 'users', 'devices']:
        command += ['--' + key, str(data[key])]
    command += ['--arms', ','.join(data['arms']), '--attacks', ','.join(data['attacks']) or 'none']
    try:
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        for line in process.stdout:
            with lock:
                jobs[name]['output'] = (jobs[name]['output'] + [line.rstrip()])[-250:]
        status = 'complete' if process.wait() == 0 else 'failed'
    except Exception as error:
        with lock:
            jobs[name]['output'].append(str(error))
        status = 'failed'
    with lock:
        jobs[name]['status'] = status


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            url = urlparse(self.path)
            if url.path == '/api/policy':
                return self.respond(200, policy())
            if url.path == '/api/runs':
                result = []
                for path in sorted(RUNS.glob('*'), reverse=True):
                    if path.is_dir() and not path.is_symlink() and (path / 'config.json').exists():
                        try:
                            result.append(detail(path))
                        except (ValueError, OSError):
                            continue
                with lock:
                    known = {r['id'] for r in result}
                    for name, job in jobs.items():
                        if name not in known:
                            result.append({'id': name, 'config': job['config'], 'utility': [],
                                           'privacy': [], 'status': job['status'], 'output': list(job['output'])})
                return self.respond(200, sorted(result, key=lambda r: r['config'].get('created_at', ''), reverse=True))
            chart = re.fullmatch(r'/api/runs/([^/]+)/plots/([a-z-]+)\.(png|json)', url.path)
            replay = re.fullmatch(r'/api/runs/([^/]+)/sensitivity', url.path)
            if chart or replay:
                from analysis_plots import render_plot, sensitivity, variant_series, tradeoff_plot
                path = run_path((chart or replay)[1])
                parameters = parse_qs(url.query)
                data = detail(path)
                if data['status'] != 'complete':
                    raise ValueError('Complete this experiment before analyzing it')
                factor = parameters.get('factor', ['spray'])[0]
                if replay:
                    return self.respond(200, sensitivity(path, factor))
                kind = chart[2]
                if kind == 'tradeoff':
                    body, points, width, height = tradeoff_plot(data, parameters.get('label', [''])[0], parameters.get('metric', ['f1'])[0])
                    if chart[3] == 'json':
                        return self.respond(200, {'image': base64.b64encode(body).decode('ascii'), 'points': points, 'width': width, 'height': height})
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/png')
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(body)
                    return
                arm = parameters.get('arm', ['raw'])[0]
                metric = parameters.get('metric', ['f1'])[0]
                plotted = sensitivity(path, factor) if kind == 'sensitivity' else None
                if kind == 'sensitivity-variants':
                    requested = json.loads(parameters.get('variants', ['[]'])[0])
                    if not isinstance(requested, list) or not 1 <= len(requested) <= 100:
                        raise ValueError('Select between 1 and 100 matched experiments')
                    items = []
                    for item in requested:
                        if not isinstance(item, dict) or not re.fullmatch(r'E[1-9][0-9]*', str(item.get('label', ''))):
                            raise ValueError('Invalid experiment label')
                        saved = detail(run_path(item.get('id', '')))
                        if saved['status'] != 'complete':
                            raise ValueError('Only completed experiments can be compared')
                        items.append((saved, item['label']))
                    plotted = variant_series(items, data['id'], metric)
                body = render_plot(kind, data, arm=arm,
                                   replay=plotted, metric=metric, label=parameters.get('label', [''])[0])
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Disposition', f'inline; filename="{path.name}-{kind}-{arm}.png"')
                self.end_headers()
                self.wfile.write(body)
                return
            match = re.fullmatch(r'/api/runs/([^/]+)(/events|/incidents|/policy)?', url.path)
            if match:
                path = run_path(match[1])
                if not match[2]:
                    return self.respond(200, detail(path))
                if match[2] == '/policy':
                    return self.respond(200, policy(path))
                parameters = parse_qs(url.query)
                arm = parameters.get('arm', ['raw'])[0]
                if arm not in ARMS:
                    raise ValueError('Invalid arm')
                if match[2] == '/incidents':
                    return self.respond(200, incident_page(path, arm, int(parameters.get('page', ['1'])[0]),
                                                          parameters.get('q', [''])[0]))
                release = path / 'releases' / f'{arm}_{path.name}.jsonl'
                return self.respond(200, event_page(release, int(parameters.get('page', ['1'])[0]),
                                                    parameters.get('q', [''])[0]))
            self.respond(404, {'error': 'Not found'})
        except ImportError:
            self.respond(503, {'error': 'Install the Python chart dependencies from requirements.txt, then restart the API.'})
        except (ValueError, OSError, KeyError) as error:
            self.respond(400, {'error': str(error)})

    def do_POST(self):
        # JSON + same-origin checks prevent a third-party page starting local jobs.
        origin = self.headers.get('Origin')
        if origin and origin not in {'http://127.0.0.1:5173', 'http://localhost:5173', 'http://127.0.0.1:8765'}:
            return self.respond(403, {'error': 'Origin not allowed'})
        if self.path != '/api/runs':
            return self.respond(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192 or self.headers.get('Content-Type') != 'application/json':
                raise ValueError('A small JSON request is required')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Expected settings object')
            validate(data)
            with lock:
                if any(j['status'] == 'running' for j in jobs.values()):
                    return self.respond(409, {'error': 'An experiment is already running.'})
                name = new_run_id(data['seed'], data['events'])
                jobs[name] = {'status': 'running', 'output': [], 'config': {
                    **data, 'created_at': datetime.now().astimezone().isoformat(),
                    'arms': ','.join(data['arms']), 'attacks': ','.join(data['attacks']) or 'none'}}
            threading.Thread(target=execute, args=(name, data), daemon=True).start()
            self.respond(202, {'id': name})
        except (ValueError, TypeError) as error:
            self.respond(400, {'error': str(error)})


if __name__ == '__main__':
    print('PseudoTracer local API: http://127.0.0.1:8765', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
