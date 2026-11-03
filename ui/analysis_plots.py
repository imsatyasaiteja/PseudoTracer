"""Analyze-only scientific plots and read-only threshold replays."""
from copy import deepcopy
from functools import lru_cache
from io import BytesIO
from pathlib import Path
import json
import math
import re
import threading

import yaml

ARMS = ('raw', 'masked', 'hmac')
COLORS = {'raw': '#7990ad', 'masked': '#a88bdc', 'hmac': '#60e2bb'}
SCENARIOS = ('password_spray', 'mfa_fatigue', 'impossible_travel', 'credential_compromise')
LABELS = ('Password\nspray', 'MFA\nfatigue', 'Impossible\ntravel', 'Credential\ncompromise')
FACTORS = {
    'spray': ('password_spray', 'min_users', 'Password-spray user threshold'),
    'mfa': ('mfa_fatigue', 'min_denials', 'MFA-denial threshold'),
    'failures': ('credential_compromise', 'min_failures', 'Password-failure threshold'),
    'travel': ('impossible_travel', 'window_minutes', 'Impossible-travel window (minutes)'),
}
PRIVACY = (
    ('Re-identification\nsuccess', 'reidentification_success_rate', 'reidentification_correct', 'reidentification_attempts'),
    ('Direct identifier\nleakage', 'direct_identifier_leakage', 'direct_identifiers_disclosed', 'direct_identifiers_total'),
    ('Frequency\ninference', 'frequency_inference_risk', 'frequency_correct', 'frequency_attempts'),
    ('Profile linkage', 'auxiliary_linkage_success', 'auxiliary_correct', 'auxiliary_attempts'),
    ('Composite linkage', 'composite_auxiliary_linkage_success', 'composite_auxiliary_correct', 'composite_auxiliary_attempts'),
    ('Snapshot linkability', 'cross_snapshot_linkability', 'snapshot_linked_users', 'snapshot_eligible_users'),
)
METRICS = {'f1': 'F1 score', 'precision': 'Precision', 'recall': 'Recall', 'false_positive_rate': 'False-positive rate'}
plot_lock = threading.Lock()
replay_lock = threading.Lock()


def value(raw):
    if raw is None or isinstance(raw, bool) or raw == '':
        return None
    try:
        number = float(raw)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def integer(raw):
    number = value(raw)
    return int(number) if number is not None and number >= 0 and number.is_integer() else None


def rate(row, field, top, bottom):
    numerator, denominator = value(row.get(top)), value(row.get(bottom))
    if denominator == 0:
        return None
    result = numerator / denominator if numerator is not None and denominator is not None and denominator > 0 else value(row.get(field))
    return result if result is not None and 0 <= result <= 1 else None


def utility_rate(row, metric):
    if metric == 'f1':
        tp, predicted, actual = (value(row.get(k)) for k in ('true_positive_events', 'predicted_events', 'attack_events'))
        if all(v is not None for v in (tp, predicted, actual)):
            return 2 * tp / (predicted + actual) if predicted + actual else None
    pairs = {'precision': ('true_positive_events', 'predicted_events'), 'recall': ('true_positive_events', 'attack_events'),
             'false_positive_rate': ('false_positive_events', 'normal_events')}
    return rate(row, metric, *pairs[metric]) if metric in pairs else value(row.get(metric))


def confusion_counts(row):
    tp, fp, fn, normal = (integer(row.get(k)) for k in ('true_positive_events', 'false_positive_events', 'false_negative_events', 'normal_events'))
    tn = normal - fp if normal is not None and fp is not None and normal >= fp else None
    return [[tn, fp], [fn, tp]]


def threshold_levels(baseline, factor):
    multipliers = (.25, .5, 1, 1.5, 2) if factor == 'travel' else (.5, .75, 1, 1.5, 3)
    return sorted({max(1, round(baseline * multiplier)) for multiplier in multipliers})


def sensitivity(path, factor):
    if factor not in FACTORS:
        raise ValueError('Unknown sensitivity parameter')
    config = json.loads((path / 'config.json').read_text(encoding='utf-8'))
    arms = tuple(arm for arm in ARMS if arm in config.get('arms', '').split(','))
    files = [path / 'configs' / 'correlation.yaml', path / 'ground_truth' / 'truth.jsonl']
    files.extend(path / 'releases' / f'{arm}_{path.name}.jsonl' for arm in arms)
    # Include engine versions in the key; replay never writes stored experiments.
    engine = Path(__file__).resolve().parents[1] / 'src'
    files.extend([engine / 'correlation.py', engine / 'utility_metrics.py'])
    stamps = tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    with replay_lock:
        return _replay(path.name, factor, arms, stamps)


@lru_cache(maxsize=12)
def _replay(run_id, factor, arms, stamps):
    from correlation import correlate, read_jsonl
    from utility_metrics import score
    config = yaml.safe_load(Path(stamps[0][0]).read_text(encoding='utf-8'))
    scenario, field, label = FACTORS[factor]
    baseline = integer(config.get(scenario, {}).get(field))
    if not baseline or not arms:
        raise ValueError('Saved rule configuration is unavailable')
    truth = read_jsonl(Path(stamps[1][0]))
    levels, rows = threshold_levels(baseline, factor), []
    for index, arm in enumerate(arms):
        events = read_jsonl(Path(stamps[2 + index][0]))
        for setting in levels:
            changed = deepcopy(config)
            changed[scenario][field] = setting
            incidents = correlate(events, changed)
            measured = score(arm, incidents, truth, scenario)
            rows.append({**measured, 'value': setting})
    return {'run_id': run_id, 'factor': factor, 'label': label, 'scenario': scenario, 'baseline': baseline,
            'levels': levels, 'rows': rows, 'mode': 'Saved-event replay', 'arms': arms}


def variant_series(items, selected_id, metric):
    """Plot saved, matched experiment outcomes without inventing parameter trials."""
    privacy_metric = next((p for p in PRIVACY if p[1] == metric), None)
    if metric not in METRICS and privacy_metric is None:
        raise ValueError('Invalid sensitivity outcome')
    rows, released, baseline = [], set(), None
    for index, (run, label) in enumerate(items):
        if run['id'] == selected_id:
            baseline = index
        for arm in run['config'].get('arms', '').split(','):
            if arm not in ARMS:
                continue
            released.add(arm)
            source = run.get('privacy' if privacy_metric else 'utility') or []
            row = next((r for r in source if r['arm'] == arm and (privacy_metric or r.get('scenario') == 'all')), {})
            measured = rate(row, *privacy_metric[1:]) if privacy_metric else utility_rate(row, metric)
            rows.append({'arm': arm, 'value': index, 'measured': measured})
    if baseline is None:
        raise ValueError('Comparison must include the selected experiment')
    return {'rows': rows, 'arms': [a for a in ARMS if a in released], 'levels': list(range(len(items))),
            'baseline': baseline, 'tick_labels': [label for _, label in items], 'label': 'Experiment'}


def tradeoff_plot(run, label='', metric='f1'):
    if label and not re.fullmatch(r'E[1-9][0-9]*', label):
        raise ValueError('Invalid experiment label')
    if metric not in METRICS:
        raise ValueError('Invalid correlation metric')
    payload = {key: run.get(key) for key in ('id', 'config', 'utility', 'privacy')}
    with plot_lock:
        return _tradeoff_plot(json.dumps(payload, sort_keys=True), label, metric)


@lru_cache(maxsize=24)
def _tradeoff_plot(payload, label, metric):
    """A real PNG and matching pixel hit targets; offsets never change the measurements."""
    import matplotlib
    matplotlib.use('Agg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.patches import Circle, Patch
    from matplotlib.transforms import IdentityTransform
    from matplotlib.ticker import PercentFormatter
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    run = json.loads(payload)
    palette = ['#79a9ff', '#f3bd6a', '#ba93ed', '#ef89b7', '#58ced2', '#91c572']
    fig = Figure(figsize=(10, 7.5), dpi=180, facecolor='white')
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(111)
    # Both the full PNG and the plotting area have a 4:3 width-to-height ratio.
    fig.subplots_adjust(left=.09, right=.73, top=.84, bottom=.20)
    ax.set_facecolor('white')
    ax.set_xlim(-.20, 1.20)
    ax.set_ylim(-.20, 1.20)
    ax.set_xticks([0, .25, .5, .75, 1])
    ax.set_yticks([0, .25, .5, .75, 1])
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    direction = 'lower is better' if metric == 'false_positive_rate' else 'higher is better'
    ax.set_xlabel(f'{METRICS[metric]} ({direction})', color='#243447', fontsize=11, labelpad=10)
    ax.set_ylabel('Privacy attack rate', color='#243447', fontsize=11, labelpad=10)
    ax.tick_params(colors='#526273', labelsize=10, length=0, pad=7)
    # A qualitative backdrop, not an additional measured score. FPR reverses utility.
    xs, ys = np.meshgrid(np.linspace(-.2, 1.2, 400), np.linspace(-.2, 1.2, 400))
    utility = 1 - np.clip(xs, 0, 1) if metric == 'false_positive_rate' else np.clip(xs, 0, 1)
    favorability = (utility + 1 - np.clip(ys, 0, 1)) / 2
    background = LinearSegmentedColormap.from_list('tradeoff_zones', ['#ef7773', '#f6d875', '#70bd98'])
    ax.imshow(favorability, origin='lower', extent=(-.2, 1.2, -.2, 1.2), cmap=background, vmin=0, vmax=1, alpha=.28, aspect='auto', zorder=0)
    ax.grid(color='white', linewidth=.6, alpha=.8, zorder=1)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.suptitle('Privacy-Correlation Trade-off', color='#243447', fontsize=15, fontweight='bold', y=.97)
    fig.text(.41, .09, label, ha='center', fontsize=11, color='#243447', fontweight='bold')
    fig.legend(handles=[Patch(facecolor=color, label=risk[0].replace('\n', ' ').replace('Direct identifier leakage', 'Direct identifier\nleakage').replace('Re-identification success', 'Re-identification\nsuccess')) for color, risk in zip(palette, PRIVACY)],
               title='Privacy risks', title_fontsize=11, loc='center left', bbox_to_anchor=(.76, .53), ncol=1, frameon=False,
               fontsize=10, labelcolor='#243447', labelspacing=1.5, handlelength=1, handletextpad=.8)
    fig.canvas.draw()
    width, height = fig.canvas.get_width_height()
    points = []
    released = set((run.get('config') or {}).get('arms', '').split(','))
    for index, (name, field, numerator, denominator) in enumerate(PRIVACY):
        for arm in ARMS:
            if arm not in released:
                continue
            utility = next((r for r in run.get('utility') or [] if r['arm'] == arm and r.get('scenario') == 'all'), {})
            privacy = next((r for r in run.get('privacy') or [] if r['arm'] == arm), {})
            x, y, total = utility_rate(utility, metric), rate(privacy, field, numerator, denominator), value(privacy.get(denominator))
            if x is None or y is None or total is None or total <= 0 or not 0 <= x <= 1:
                continue
            axx, axy = ax.transData.transform((x, y))
            correct = value(privacy.get(numerator))
            result = f'{correct:,.0f} / {total:,.0f}' if correct is not None else f'{y:.1%}'
            points.append({'id': f'{field}:{arm}', 'arm': arm, 'color': palette[index], 'anchor': (float(axx), float(axy)),
                           'denominator': total, 'description': f"{label}, {arm.upper()}, {name.replace(chr(10), ' ')}: {result}; {METRICS[metric]} {x:.1%}"})
    maximum = max((p['denominator'] for p in points), default=1)
    for p in points:
        p['radius'] = max(19, 34 * math.sqrt(p['denominator'] / maximum))
        p['shared'] = sum(math.dist(p['anchor'], q['anchor']) < 1e-6 for q in points) > 1
    # Reserve singleton positions first so displaced clusters cannot cover them.
    placed = [{**p, 'x': p['anchor'][0], 'y': p['anchor'][1]} for p in points if not p['shared']]
    for p in (p for p in points if p['shared']):
        radius = p['radius']
        anchor_x, anchor_y = p['anchor']
        selected = None
        for ring in range(1, 30):
            for j in range(ring * 12):
                angle = j * 2 * math.pi / (ring * 12)
                x, y = anchor_x + math.cos(angle) * ring * 48, anchor_y + math.sin(angle) * ring * 48
                if not (ax.bbox.x0 + radius < x < ax.bbox.x1 - radius and ax.bbox.y0 + radius < y < ax.bbox.y1 - radius):
                    continue
                if any(math.hypot(x-q['anchor'][0], y-q['anchor'][1]) < radius + 8 for q in points):
                    continue
                if any(math.hypot(x-q['x'], y-q['y']) < radius + q['radius'] + 7 for q in placed):
                    continue
                selected = (x, y)
                break
            if selected:
                break
        if selected is None:
            raise ValueError('Unable to separate chart bubbles')
        placed.append({**p, 'x': selected[0], 'y': selected[1], 'radius': radius})
    for p in placed:
        if p['shared']:
            ax.plot([p['anchor'][0], p['x']], [p['anchor'][1], p['y']], transform=IdentityTransform(), color='white', linewidth=1, zorder=2)
            ax.add_patch(Circle(p['anchor'], 3, transform=IdentityTransform(), color='white', zorder=2))
    targets = []
    for p in placed:
        ax.add_patch(Circle((p['x'], p['y']), p['radius'], transform=IdentityTransform(), facecolor=p['color'], edgecolor='#475569', linewidth=.6, zorder=3))
        ax.text(p['x'], p['y'], p['arm'][0].upper(), transform=IdentityTransform(), ha='center', va='center', color='#152233', fontsize=10, fontweight='bold', zorder=4)
        targets.append({'id': p['id'], 'x': p['x'], 'y': height-p['y'], 'radius': p['radius'], 'description': p['description'],
                        'anchor_x': p['anchor'][0], 'anchor_y': height-p['anchor'][1], 'displaced': p['shared']})
    if not points:
        ax.text(.5, .5, 'No paired measurements with an eligible denominator', transform=ax.transAxes, ha='center', color='#526273', fontsize=11)
    output = BytesIO()
    fig.savefig(output, format='png', dpi=180, facecolor='white', metadata={'Software': 'PseudoTracer / Matplotlib', 'Experiment': run['id'], 'Experiment label': label, 'Correlation metric': metric})
    fig.clear()
    return output.getvalue(), targets, width, height


def render_plot(kind, run, arm='raw', replay=None, metric='f1', label=''):
    if kind not in ('successful', 'false-alerts', 'missed', 'detection', 'privacy', 'sensitivity', 'sensitivity-variants'):
        raise ValueError('Unknown plot')
    allowed = set(METRICS) | ({p[1] for p in PRIVACY} if kind == 'sensitivity-variants' else set())
    if arm not in ARMS or metric not in allowed or (label and not re.fullmatch(r'E[1-9][0-9]*', label)):
        raise ValueError('Invalid plot option')
    payload = {key: run.get(key) for key in ('id', 'config', 'utility', 'privacy')}
    # Serialize identical payloads to reuse PNGs across page switches and refreshes.
    with plot_lock:
        return _render(kind, json.dumps(payload, sort_keys=True), arm, json.dumps(replay, sort_keys=True), metric, label)


@lru_cache(maxsize=48)
def _render(kind, payload, arm, replay_json, metric, label):
    import matplotlib
    matplotlib.use('Agg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.colors import LinearSegmentedColormap
    from matplotlib.ticker import MaxNLocator, PercentFormatter
    import numpy as np
    import seaborn as sns
    from sklearn.metrics import ConfusionMatrixDisplay

    run, replay = json.loads(payload), json.loads(replay_json)
    released = set((run.get('config') or {}).get('arms', '').split(','))
    background, ink = '#ffffff', '#243447'
    fig = Figure(figsize=(6.4, 6.4), dpi=180, facecolor=background)
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(111)
    fig.subplots_adjust(left=.13, right=.96, top=.86, bottom=.29)
    ax.set_facecolor(background)
    ax.tick_params(colors=ink, labelsize=10, length=0, pad=9)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.xaxis.label.set_color(ink)
    ax.yaxis.label.set_color(ink)
    fig.text(.5, .135 if kind not in ('detection', 'privacy') else .045, label, ha='center', color=ink, fontsize=11, fontweight='bold')
    rows = run.get('utility') or []
    privacy = run.get('privacy') or []
    gradient = LinearSegmentedColormap.from_list('risk_rainbow', ['#eff3ff', '#a8d5ee', '#76bdac', '#eac560', '#d78148', '#853449'])

    if kind in ('successful', 'false-alerts', 'missed'):
        field, title = {'successful': ('true_positive_events', 'Successful Detection'), 'false-alerts': ('false_positive_events', 'False Alerts'), 'missed': ('false_negative_events', 'Missed Alerts')}[kind]
        highest = 0
        for index, technique in enumerate(ARMS):
            values = [integer(next((r for r in rows if r['arm'] == technique and r['scenario'] == scenario), {}).get(field)) if technique in released else None for scenario in SCENARIOS]
            x = np.arange(4) + (index - 1) * .24
            bars = ax.bar(x, [v if v is not None else 0 for v in values], width=.2, color=COLORS[technique], label=technique.upper(), zorder=3)
            ax.bar_label(bars, labels=[f'{v:,}' if v is not None else 'N/A' for v in values], color=COLORS[technique], fontsize=9, padding=6)
            highest = max(highest, *(v or 0 for v in values))
        ax.set_xticks(np.arange(4), LABELS)
        ax.set_ylabel('Total Events', fontsize=12, labelpad=10)
        ax.set_ylim(0, max(1, highest * 1.25))
        ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
        ax.grid(axis='y', color='#dce3e9', linestyle='--', zorder=0)
        fig.legend(loc='lower center', bbox_to_anchor=(.5, .04), ncol=3, frameon=False, labelcolor=ink, fontsize=10)
    elif kind == 'detection':
        title = f'Detection Confusion Matrix - {arm.upper()}'
        fig.subplots_adjust(left=.18, right=.84, top=.85, bottom=.18)
        row = next((r for r in rows if r['arm'] == arm and r['scenario'] == 'all'), {}) if arm in released else {}
        matrix = confusion_counts(row)
        maximum = max(1, *(v for r in rows if r.get('scenario') == 'all' and r.get('arm') in released for line in confusion_counts(r) for v in line if v is not None))
        if all(v is not None for line in matrix for v in line):
            display = ConfusionMatrixDisplay(np.array(matrix, dtype=int), display_labels=['Normal', 'Attack'])
            display.plot(ax=ax, cmap=gradient, colorbar=False, values_format='d', im_kw={'vmin': 0, 'vmax': maximum})
            for text in display.text_.flat:
                text.set_fontsize(17)
        else:
            array = np.array([[v if v is not None else np.nan for v in line] for line in matrix])
            ax.imshow(np.ma.masked_invalid(array), cmap=gradient, vmin=0, vmax=maximum)
            for y in range(2):
                for x in range(2):
                    ax.text(x, y, 'N/A' if matrix[y][x] is None else f'{matrix[y][x]:,}', ha='center', va='center', fontsize=17)
            ax.set_xticks([0, 1], ['Normal', 'Attack'])
            ax.set_yticks([0, 1], ['Normal', 'Attack'])
        ax.set_xlabel('Predicted', fontsize=12, labelpad=12)
        ax.set_ylabel('Actual', fontsize=12, labelpad=12)
        from matplotlib.cm import ScalarMappable
        fig.colorbar(ScalarMappable(norm=matplotlib.colors.Normalize(0, maximum), cmap=gradient), ax=ax, fraction=.046, pad=.04).set_label('Events')
    elif kind == 'privacy':
        title = 'Privacy Attack Rates'
        matrix, annotations = [], []
        for risk_label, field, top, bottom in PRIVACY:
            values = [rate(next((r for r in privacy if r['arm'] == a), {}), field, top, bottom) if a in released else None for a in ARMS]
            matrix.append([v if v is not None else np.nan for v in values])
            annotations.append([f'{v:.1%}' if v is not None else 'N/A' for v in values])
        fig.subplots_adjust(left=.3, right=.94, top=.85, bottom=.16)
        sns.heatmap(np.array(matrix), ax=ax, vmin=0, vmax=1, cmap=gradient, annot=np.array(annotations), fmt='',
                    linewidths=2, linecolor='white', xticklabels=[a.upper() for a in ARMS], yticklabels=[p[0] for p in PRIVACY],
                    annot_kws={'size': 11}, cbar_kws={'format': PercentFormatter(1), 'shrink': .8, 'label': 'Risk rate'})
        for y, line in enumerate(matrix):
            for x, v in enumerate(line):
                if np.isnan(v):
                    ax.text(x + .5, y + .5, 'N/A', ha='center', va='center', color='#667788', fontsize=11)
        ax.tick_params(axis='y', rotation=0, labelsize=10)
        ax.tick_params(axis='x', rotation=0)
    else:
        if not replay:
            raise ValueError('No sensitivity replay')
        metric_label = METRICS.get(metric) or next(p[0].replace('\n', ' ') for p in PRIVACY if p[1] == metric)
        title = f'{metric_label} sensitivity'
        fig.subplots_adjust(left=.18, right=.95, top=.85, bottom=.30)
        for technique in replay['arms']:
            series = sorted((r for r in replay['rows'] if r['arm'] == technique), key=lambda r: r['value'])
            values = [r.get('measured') if kind == 'sensitivity-variants' else utility_rate(r, metric) for r in series]
            # Different line/marker styles keep equal RAW and HMAC series visible.
            index = ARMS.index(technique)
            ax.plot([r['value'] for r in series], [np.nan if v is None else v for v in values], color=COLORS[technique],
                    label=technique.upper(), marker=('o', 's', 'D')[index], markersize=(10, 7, 4)[index],
                    linewidth=(3, 2, 1.5)[index], linestyle=('-', '--', ':')[index])
        if replay.get('baseline') is not None:
            ax.axvline(replay['baseline'], color='#657786', linewidth=1, linestyle='--', alpha=.7)
        ax.set_xticks(replay['levels'], replay.get('tick_labels', replay['levels']))
        ax.set_xlabel(replay['label'], fontsize=11, labelpad=12)
        ax.set_ylabel(metric_label, fontsize=12, labelpad=10)
        ax.set_ylim(-.04, 1.08)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.grid(color='#dce3e9', linestyle='--')
        fig.legend(loc='lower center', bbox_to_anchor=(.5, .04), ncol=3, frameon=False, labelcolor=ink, fontsize=10)
    fig.suptitle(title, color=ink, fontsize=15, fontweight='bold', y=.96)
    output = BytesIO()
    fig.savefig(output, format='png', dpi=180, facecolor=background, metadata={'Software': 'PseudoTracer / Matplotlib', 'Experiment': run['id'], 'Experiment label': label})
    fig.clear()
    return output.getvalue()
