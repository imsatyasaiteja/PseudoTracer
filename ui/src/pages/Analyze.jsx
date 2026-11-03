import React, { useEffect, useRef, useState } from 'react';
import { arms, attacks, attackLabels, number, percent, runArms, api } from '../shared';
import { Download } from 'lucide-react';

const numeric = value => (typeof value === 'number' || (typeof value === 'string' && value.trim())) && Number.isFinite(Number(value)) ? Number(value) : null;
const count = field => row => numeric(row[field]);
const sum = (a, b) => numeric(a) !== null && numeric(b) !== null ? Number(a) + Number(b) : null;
export const techniqueColors = { raw: '#7990ad', masked: '#a88bdc', hmac: '#60e2bb' };
export const detectionMetrics = [
    { key: 'f1', label: 'F1 score', numerator: row => numeric(row.true_positive_events) === null ? null : 2 * Number(row.true_positive_events), denominator: row => sum(row.predicted_events, row.attack_events) },
    { key: 'precision', label: 'Precision', numerator: count('true_positive_events'), denominator: count('predicted_events') },
    { key: 'recall', label: 'Recall', numerator: count('true_positive_events'), denominator: count('attack_events') },
    { key: 'false_positive_rate', label: 'False-positive rate', numerator: count('false_positive_events'), denominator: count('normal_events') },
].map(metric => ({ ...metric, source: 'utility' }));
const incidentRecall = { key: 'incident_recall', label: 'Incident recall', source: 'utility', numerator: count('incidents_detected'), denominator: count('actual_incidents') };
export const privacyMetrics = [
    ['reidentification_success_rate', 'Re-identification success', 'reidentification_correct', 'reidentification_attempts', 'Correct identity guesses / evaluated guesses'],
    ['direct_identifier_leakage', 'Direct identifier leakage', 'direct_identifiers_disclosed', 'direct_identifiers_total', 'Disclosed source field/value pairs / all distinct source field/value pairs'],
    ['frequency_inference_risk', 'Frequency inference', 'frequency_correct', 'frequency_attempts', 'Correct frequency guesses / evaluated guesses'],
    ['auxiliary_linkage_success', 'Profile linkage', 'auxiliary_correct', 'auxiliary_attempts', 'Correct profile guesses / evaluated guesses'],
    ['composite_auxiliary_linkage_success', 'Composite linkage', 'composite_auxiliary_correct', 'composite_auxiliary_attempts', 'Correct composite guesses / evaluated guesses'],
    ['cross_snapshot_linkability', 'Snapshot linkability', 'snapshot_linked_users', 'snapshot_eligible_users', 'Users linked across windows / users present in both windows'],
].map(([key, label, top, bottom, definition], index) => ({ key, label, definition, source: 'privacy',
    numerator: count(top), denominator: count(bottom), color: ['#79a9ff', '#f3bd6a', '#ba93ed', '#ef89b7', '#58ced2', '#91c572'][index] }));

export function readMeasurement(run, arm, metric) {
    const missing = reason => ({ value: null, numerator: null, denominator: null, reason });
    if (!run || !runArms(run).includes(arm)) return missing('Technique not released');
    const row = (run[metric.source] || []).find(item => item.arm === arm && (metric.source !== 'utility' || item.scenario === 'all'));
    if (!row) return missing('Measurement not recorded');
    const numerator = metric.numerator(row), denominator = metric.denominator(row);
    if ((numerator !== null && numerator < 0) || (denominator !== null && denominator < 0) || (numerator !== null && denominator !== null && numerator > denominator)) return missing('Invalid measurement');
    if (denominator === 0) return { value: null, numerator, denominator, reason: 'No eligible observations' };
    const value = numerator !== null && denominator !== null ? numerator / denominator : numeric(row[metric.key]);
    if (value === null || value < 0 || value > 1) return missing('Measurement not recorded');
    return { value, numerator, denominator, reason: '' };
}
export function analysisExperiments(runs) {
    const time = run => Date.parse(run.config.created_at) || 0;
    return runs.filter(run => run.status === 'complete').sort((a, b) => time(a) - time(b) || a.id.localeCompare(b.id)).map((run, index) => ({ run, label: `E${index + 1}` }));
}
export const experimentName = item => item ? `${item.label} (${item.run.id})` : 'No completed experiments';
function measurementText(m) {
    return (m.value === null ? 'N/A' : percent(m.value)) + (m.numerator !== null && m.denominator !== null ? ` (${number(m.numerator)} / ${number(m.denominator)})` : '');
}
function ExperimentSelect({ experiments, value, onChange }) {
    return <label className="analysis-field experiment-select"><span>Experiment</span><select value={value || ''} disabled={!experiments.length} onChange={e => onChange(e.target.value)}>
        {!experiments.length && <option value="">No completed experiments</option>}
        {experiments.map(item => <option key={item.run.id} value={item.run.id}>{experimentName(item)}</option>)}
    </select></label>;
}
function TechniqueLegend({ selected, onSelect }) {
    return <div className="technique-legend" aria-label="Release techniques">{arms.map(arm => onSelect ?
        <button key={arm} type="button" aria-pressed={selected === arm} className={selected === arm ? 'active' : ''} onClick={() => onSelect(arm)}><i style={{ background: techniqueColors[arm] }} />{arm.toUpperCase()}</button> :
        <span key={arm}><i style={{ background: techniqueColors[arm] }} />{arm.toUpperCase()}</span>)}</div>;
}
function Empty({ children = 'Complete an experiment to see measured results.' }) { return <div className="analysis-empty">{children}</div>; }
function ChartCard({ title, children, className = '', actions }) { return <section className={`panel analysis-card ${className}`}>{actions ? <div className="analysis-card-heading"><h2>{title}</h2>{actions}</div> : <h2>{title}</h2>}{children}</section>; }

// Research summary
export function summaryInterpretation(run) {
    const best = (metric, high) => {
        const values = runArms(run).map(arm => ({ arm, value: readMeasurement(run, arm, metric).value })).filter(item => item.value !== null);
        if (!values.length) return 'N/A';
        const extreme = (high ? Math.max : Math.min)(...values.map(item => item.value));
        return values.filter(item => Math.abs(item.value - extreme) < 1e-9).map(item => item.arm.toUpperCase()).join(' / ');
    };
    const measured = runArms(run).map(arm => ({ arm, f1: readMeasurement(run, arm, detectionMetrics[0]).value,
        leakage: readMeasurement(run, arm, privacyMetrics[1]).value, linkage: readMeasurement(run, arm, privacyMetrics[5]).value }));
    const complete = measured.filter(item => item.f1 !== null && item.leakage !== null && item.linkage !== null);
    const names = items => items.map(item => item.arm.toUpperCase()).join(' / ');
    let outcome = 'The recorded outcomes are insufficient to compare detection utility, direct leakage and snapshot linkability together.';
    if (complete.length === 1) outcome = `Only ${names(complete)} has all three measurements. A privacy–utility trade-off cannot be established against other releases yet.`;
    if (complete.length > 1) {
        const leaders = complete.filter(item => item.f1 === Math.max(...complete.map(v => v.f1)));
        const safest = complete.filter(item => item.leakage === Math.min(...complete.map(v => v.leakage)) && item.linkage === Math.min(...complete.map(v => v.linkage)));
        const balanced = safest.filter(item => leaders.includes(item));
        const equal = complete.every(item => ['f1', 'leakage', 'linkage'].every(key => item[key] === complete[0][key]));
        if (equal) outcome = 'The releases are indistinguishable on measured F1, direct leakage and snapshot linkability; this experiment does not demonstrate a privacy–utility advantage for one technique.';
        else if (balanced.length) outcome = `${names(balanced)} combines the strongest measured detection performance with the lowest direct leakage and snapshot linkability. This experiment shows no F1 penalty for choosing it over the other measured releases.`;
        else {
            outcome = `${names(leaders)} provides the strongest detection performance. `;
            if (safest.length) {
                const gap = (leaders[0].f1 - Math.max(...safest.map(item => item.f1))) * 100;
                outcome += `${names(safest)} minimizes both measured privacy risks, at a cost of ${gap.toFixed(1)} percentage points of F1. `;
            } else outcome += 'No release minimizes both direct leakage and snapshot linkability, so the privacy choice depends on which exposure matters most. ';
        }
        const residual = leaders.filter(item => item.leakage === 0 && item.linkage > 0);
        if (residual.length) outcome += ` ${names(residual)} exposes no measured direct identifiers, but still links users across snapshots; hiding identities has not removed continuity of tracking.`;
        else if (balanced.length && balanced.some(item => item.leakage > 0 || item.linkage > 0)) outcome += ' Lowest observed risk is relative: some identity exposure or cross-snapshot tracking remains.';
        if (complete.length < measured.length) outcome += ' Releases with incomplete measurements are excluded from this comparison.';
    }
    return [['Best utility (F1)', best(detectionMetrics[0], true)], ['Lowest direct leakage', best(privacyMetrics[1], false)],
        ['Highest snapshot linkage risk', best(privacyMetrics[5], true)], ['Main trade-off', outcome || 'No comparable measurements in this experiment.']];
}
export function ResearchSummary({ run }) {
    const metrics = [['Correlation F1', detectionMetrics[0]], ['Incident recall', incidentRecall], ['Direct identifier leakage', privacyMetrics[1]], ['Snapshot linkability', privacyMetrics[5]]];
    return <div className="research-summary">
        <ChartCard title="Research Summary"><div className="analysis-table-wrap"><table className="analysis-table" aria-label="Research summary">
            <thead><tr><th>Category</th>{arms.map(arm => <th key={arm}><span style={{ color: techniqueColors[arm] }}>{arm.toUpperCase()}</span></th>)}</tr></thead>
            <tbody>{metrics.map(([name, metric]) => <tr key={name}><th scope="row">{name}</th>{arms.map(arm => <td key={arm}>{measurementText(readMeasurement(run, arm, metric))}</td>)}</tr>)}
                <tr><th scope="row">Transformation size</th>{arms.map(arm => {
                    const row = runArms(run).includes(arm) && run?.transformation_cost?.find(item => item.arm === arm), ratio = numeric(row?.storage_ratio_to_raw);
                    return <td key={arm}>{ratio === null ? 'N/A' : arm === 'raw' ? 'Baseline (1.00x)' : `${ratio.toFixed(3)}x RAW`}{numeric(row?.release_bytes) !== null && <small>{number(row.release_bytes)} bytes</small>}</td>;
                })}</tr></tbody></table></div></ChartCard>
        <section className="panel interpretation-grid" aria-label="Experiment interpretation">{summaryInterpretation(run).map(([label, value]) => <div key={label}><span>{label}</span><p>{value}</p></div>)}</section>
    </div>;
}

// Scenario event counts
export function scenarioCounts(run, field) {
    return arms.map(arm => ({ arm, values: attacks.map(scenario => {
        const row = runArms(run).includes(arm) && run?.utility?.find(item => item.arm === arm && item.scenario === scenario);
        const value = numeric(row?.[field]);
        return Number.isSafeInteger(value) && value >= 0 ? value : null;
    }) }));
}
// Discard chart responses when the experiment selection changes.
function PythonPlot({ run, kind, arm = 'raw', factor = 'spray', metric = 'f1', label = '', variants = [], title, description = '', onPoint }) {
    const [result, setResult] = useState(null), [retry, setRetry] = useState(0);
    const host = useRef(null), [size, setSize] = useState({ width: 0, height: 0 });
    useEffect(() => {
        const observer = new ResizeObserver(([entry]) => setSize({ width: entry.contentRect.width, height: entry.contentRect.height }));
        observer.observe(host.current); return () => observer.disconnect();
    }, []);
    const payload = JSON.stringify([run?.utility, run?.privacy, run?.analysis_settings]);
    const revision = Array.from(payload).reduce((hash, char) => (Math.imul(hash, 31) + char.charCodeAt(0)) | 0, 0);
    const request = run ? `/api/runs/${encodeURIComponent(run.id)}/plots/${kind}.${kind === 'tradeoff' ? 'json' : 'png'}?${new URLSearchParams({ arm, factor, metric, label, variants: JSON.stringify(variants.map(v => ({ id: v.run.id, label: v.label }))), v: `tradeoff-v4-${revision}` })}` : '';
    useEffect(() => {
        if (!request) return;
        const controller = new AbortController();
        let alive = true, objectURL;
        setResult(null);
        fetch(request, { signal: controller.signal }).then(async response => {
            if (!response.ok) { const error = await response.json(); throw new Error(error.error || 'Plot unavailable'); }
            let blob, points = [], width = 1152, height = 1152;
            if (kind === 'tradeoff') {
                const chart = await response.json();
                blob = new Blob([Uint8Array.from(atob(chart.image), c => c.charCodeAt(0))], { type: 'image/png' });
                points = chart.points; width = chart.width; height = chart.height;
            } else {
                if (!response.headers.get('content-type')?.includes('image/png')) throw new Error('Restart the local API to enable Python plots.');
                blob = await response.blob();
            }
            if (!alive) return;
            objectURL = URL.createObjectURL(blob);
            setResult({ request, url: objectURL, points, width, height });
        }).catch(error => { if (alive && error.name !== 'AbortError') setResult({ request, error: error.message }); });
        return () => { alive = false; controller.abort(); if (objectURL) URL.revokeObjectURL(objectURL); };
    }, [request, retry]);
    const current = result?.request === request ? result : null;
    const scale = current?.url ? Math.min(size.width / current.width, size.height / current.height) : 0;
    return <div className="python-plot" ref={host}>
        {current?.url ? <><div className="python-image-layer" style={{ width: current.width * scale, height: current.height * scale }}><img src={current.url} alt={`${title} for ${label || run.id}. ${description}`} />
            {current.points.map(p => <button key={p.id} className="plot-hotspot" aria-label={p.description} style={{ left: `${100 * (p.x - p.radius) / current.width}%`, top: `${100 * (p.y - p.radius) / current.height}%`, width: `${200 * p.radius / current.width}%`, height: `${200 * p.radius / current.height}%` }}
                onMouseEnter={() => onPoint?.(p.id)} onMouseLeave={() => onPoint?.(null)} onFocus={() => onPoint?.(p.id)} onBlur={() => onPoint?.(null)} />)}</div>
            <a className="plot-download" href={current.url} download={`${run.id}-${kind}${kind === 'detection' ? `-${arm}` : kind === 'tradeoff' ? `-${metric}` : ''}.png`} title="Download PNG" aria-label={`Download ${title} as PNG`}><Download size={14} /><span>PNG</span></a></> :
            <div className="python-plot-status" role={current?.error ? 'alert' : 'status'}>{!run ? 'Select a completed experiment.' : current?.error || 'Generating Python chart...'}
                {current?.error && <button onClick={() => setRetry(value => value + 1)}>Retry</button>}</div>}
    </div>;
}
export function IncidentCorrelation({ run, label }) {
    return <div className="incident-charts">{[['Successful Detection', 'successful', 'true_positive_events'], ['False Alerts', 'false-alerts', 'false_positive_events'], ['Missed Alerts', 'missed', 'false_negative_events']].map(([title, kind, field]) =>
        <ChartCard title={title} key={kind}><PythonPlot run={run} kind={kind} title={title} label={label}
            description={scenarioCounts(run, field).map(s => `${s.arm.toUpperCase()}: ${s.values.map((v, i) => `${attackLabels[attacks[i]]} ${v === null ? 'N/A' : v}`).join(', ')}`).join('; ')} /></ChartCard>)}</div>;
}

// Privacy-correlation chart
export function tradeoffPoints(run, correlationMetric = detectionMetrics[0]) {
    return privacyMetrics.flatMap(metric => runArms(run).map(arm => {
        const utility = readMeasurement(run, arm, correlationMetric), privacy = readMeasurement(run, arm, metric);
        return { id: `${metric.key}:${arm}`, arm, metric, utility, privacy, x: utility.value, y: privacy.value, denominator: privacy.denominator };
    }));
}
export function TradeoffGraph({ run, label }) {
    const [hover, setHover] = useState(null), [metricKey, setMetricKey] = useState('f1');
    const metric = detectionMetrics.find(item => item.key === metricKey);
    useEffect(() => { setHover(null); }, [run?.id, metricKey]);
    const points = tradeoffPoints(run, metric);
    const inspect = id => setHover(points.find(p => p.id === id) || null);
    return <ChartCard title="Privacy-Correlation Trade-off" className="bubble-card" actions={
        <label className="tradeoff-metric"><span>Correlation metric</span><select value={metricKey} onChange={event => { setHover(null); setMetricKey(event.target.value); }}>
            {[detectionMetrics[0], detectionMetrics[2], detectionMetrics[3], detectionMetrics[1]].map(item => <option value={item.key} key={item.key}>{item.label}</option>)}
        </select></label>}>
        <div className="bubble-layout"><PythonPlot run={run} kind="tradeoff" metric={metricKey} label={label} title="Privacy-correlation trade-off" onPoint={inspect} />
            <section className="bubble-detail" aria-label="Point details"><h3><span aria-hidden="true">&gt;_</span><span className="terminal-title">/ <b>DETAILS</b></span></h3>
                <div aria-live="polite"><p className="terminal-prompt">C:\PseudoTracer&gt; <span>inspect {label}</span></p>
                    {hover ? <><p className="terminal-technique">{hover.arm.toUpperCase()} / {hover.metric.label}</p><dl className="terminal-readings">
                        <div><dt>{metric.label}</dt><dd>{measurementText(hover.utility)}</dd></div>
                        <div><dt>Privacy attack rate</dt><dd>{measurementText(hover.privacy)}</dd></div>
                        <div><dt>Opportunities</dt><dd>{number(hover.denominator)}</dd></div>
                    </dl><p className="terminal-definition">{hover.metric.definition}</p></> : <p>Hover a bubble to inspect its details</p>}
                    <p className="terminal-prompt">C:\PseudoTracer&gt;<span className="terminal-cursor" aria-hidden="true">_</span></p>
                </div>
            </section>
        </div>
    </ChartCard>;
}

// Confusion matrices
export function confusionCounts(run, arm) {
    const row = runArms(run).includes(arm) && run?.utility?.find(item => item.arm === arm && item.scenario === 'all');
    const tp = numeric(row?.true_positive_events), fp = numeric(row?.false_positive_events), fn = numeric(row?.false_negative_events), normal = numeric(row?.normal_events);
    const tn = normal !== null && fp !== null ? normal - fp : null;
    return [[tn, fp], [fn, tp]].map(row => row.map(value => Number.isSafeInteger(value) && value >= 0 ? value : null));
}
export function ConfusionMatrices({ run }) {
    const [chosenArm, setArm] = useState('raw');
    const arm = runArms(run).includes(chosenArm) ? chosenArm : runArms(run)[0] || 'raw';
    const counts = confusionCounts(run, arm);
    return <div className="matrix-panels"><ChartCard title="Detection Engine - Confusion Matrix">
        <TechniqueLegend selected={arm} onSelect={setArm} />
        <PythonPlot run={run} kind="detection" arm={arm} title="Detection confusion matrix"
            description={`TN ${number(counts[0][0])}, FP ${number(counts[0][1])}, FN ${number(counts[1][0])}, TP ${number(counts[1][1])}`} />
        <dl className="matrix-metrics">{[detectionMetrics[1], detectionMetrics[2], detectionMetrics[0], detectionMetrics[3]].map(metric => <div key={metric.key}><dt>{metric.label}</dt><dd>{measurementText(readMeasurement(run, arm, metric))}</dd></div>)}</dl>
    </ChartCard><ChartCard title="Privacy Attack Matrix"><div className="matrix-spacer" aria-hidden="true" />
        <PythonPlot run={run} kind="privacy" title="Privacy attack matrix" />
    </ChartCard></div>;
}

// Sensitivity: threshold replays and matched experiments
export const sensitivityFactors = [
    ['spray', 'Password-spray user threshold', 'password_spray', 'min_users'],
    ['mfa', 'MFA-denial threshold', 'mfa_fatigue', 'min_denials'],
    ['failures', 'Password-failure threshold', 'credential_compromise', 'min_failures'],
    ['travel', 'Impossible-travel window', 'impossible_travel', 'window_minutes'],
    ['events', 'Number of events'], ['users', 'Number of users'], ['devices', 'Number of devices'],
    ['intensity', 'Attack intensity'], ['policy', 'Privacy policy configuration'],
];
const stable = value => JSON.stringify(value, (_, v) => v && !Array.isArray(v) && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
export function sensitivityValue(run, factor, scenario = 'password_spray') {
    if (!run) return null;
    const [key, , attack, field] = factor;
    if (['events', 'users', 'devices'].includes(key)) return numeric(run.config[key]);
    if (attack) return numeric(run.analysis_settings?.rules?.[attack]?.[field]);
    if (key === 'policy') return run.config.config_sha256?.['privacy_policy.yaml'] || null;
    const setting = run.analysis_settings?.intensity?.[scenario];
    return setting && Object.keys(setting).length ? stable(setting) : null;
}
export function matchedVariants(experiments, run, factor, scenario = 'password_spray') {
    if (!run) return [];
    const signature = item => {
        // Missing provenance cannot establish a controlled comparison.
        if (!item.config.source_sha256 || !item.config.config_sha256 || !item.data_source?.sample_sha256) return null;
        const c = { ...item.config, config_sha256: { ...item.config.config_sha256 } };
        for (const key of ['run_id', 'created_at', 'key_path', 'rba_csv']) delete c[key];
        if (['events', 'users', 'devices'].includes(factor[0])) delete c[factor[0]];
        if (factor[0] === 'policy') delete c.config_sha256['privacy_policy.yaml'];
        if (factor[0] === 'intensity') delete c.config_sha256[`attacks/${scenario}.yaml`];
        return stable([c, item.data_source.sample_sha256]);
    };
    const base = signature(run);
    const rows = experiments.filter(item => item.run.id === run.id || (base !== null && signature(item.run) === base))
        .map(item => ({ ...item, value: sensitivityValue(item.run, factor, scenario) })).filter(item => item.value !== null);
    return rows.sort((a, b) => String(a.value).localeCompare(String(b.value), undefined, { numeric: true }));
}
function Delta({ value, baseline }) {
    if (value === null || baseline === null) return null;
    const delta = (value - baseline) * 100;
    return <small>{delta > 0 ? '+' : ''}{delta.toFixed(1)} pp</small>;
}
export function sensitivityExplanation({ run, label, factor, metric, data, variants, scenario }) {
    if (!run) return 'Select a completed experiment to inspect how its results respond to a parameter change.';
    if (factor[2]) {
        if (!data) return `${label}: preparing a ${factor[1].toLowerCase()} replay from the saved event releases.`;
        const changes = (data.arms || []).map(arm => {
            const values = data.rows.filter(row => row.arm === arm).map(row => readMeasurement({ config: { arms: arm }, utility: [{ ...row, scenario: 'all' }] }, arm, metric).value).filter(value => value !== null);
            return { arm, span: values.length > 1 ? Math.max(...values) - Math.min(...values) : null };
        }).filter(item => item.span !== null);
        const affected = changes.filter(item => item.span > 1e-9), stable = changes.filter(item => item.span <= 1e-9);
        const names = items => items.map(item => item.arm.toUpperCase()).join(' / ');
        let conclusion = !changes.length ? 'There are too few eligible measurements to establish sensitivity.' : !affected.length ? `${metric.label} is unchanged across the tested settings for ${names(stable)}. This indicates stability within this sweep, not proof that the rule is insensitive to every threshold.` :
            `${names(affected)} shows threshold-dependent ${metric.label.toLowerCase()}, with a largest observed change of ${(Math.max(...affected.map(item => item.span)) * 100).toFixed(1)} percentage points.${stable.length ? ` ${names(stable)} is unchanged within this sweep.` : ''} The selected threshold therefore matters when interpreting these results.`;
        return `${conclusion} For ${label}, the current engine replayed the saved releases and scored ${attackLabels[factor[2]]} at ${data.levels.length} ${factor[1].toLowerCase()} settings (${data.levels.join(', ')}; baseline ${data.baseline}). Released data, ground truth and other rule settings stayed fixed.`;
    }
    const matches = variants.filter(item => item.run.id !== run.id);
    const setting = factor[0] === 'intensity' ? ` for ${attackLabels[scenario]}` : '';
    if (!matches.length) return `The effect of ${factor[1].toLowerCase()}${setting} cannot yet be isolated for ${label}: no matched comparison is recorded. The graph and table show the selected experiment only; they do not establish whether changing this parameter improves ${metric.label.toLowerCase()}.`;
    const changes = matches.flatMap(item => arms.map(arm => {
        const base = readMeasurement(run, arm, metric).value, value = readMeasurement(item.run, arm, metric).value;
        return base === null || value === null ? null : Math.abs(value - base);
    }).filter(value => value !== null));
    const span = changes.length ? Math.max(...changes) : null;
    const finding = span === null ? 'Eligible paired outcomes are missing, so no effect can be concluded.' : span <= 1e-9 ? `${metric.label} is unchanged in the matched comparisons; the tested settings show no measured effect on this outcome.` : `${metric.label} changes by up to ${(span * 100).toFixed(1)} percentage points relative to ${label}, indicating that the tested ${factor[1].toLowerCase()} settings matter for this outcome.`;
    return `${finding} ${matches.length} saved experiment${matches.length === 1 ? '' : 's'} were matched to ${label}, allowing only ${factor[1].toLowerCase()}${setting} to differ while holding the seed, source sample, code fingerprint and other recorded configuration fixed.`;
}
export function SensitivityAnalysis({ experiments, run }) {
    const [factorKey, setFactorKey] = useState('spray'), [scenario, setScenario] = useState('password_spray'), [metricKey, setMetricKey] = useState('f1');
    const [response, setResponse] = useState(null), [retry, setRetry] = useState(0);
    const factor = sensitivityFactors.find(item => item[0] === factorKey), isReplay = Boolean(factor[2]);
    const options = isReplay ? detectionMetrics : [...detectionMetrics, ...privacyMetrics];
    const metric = options.find(item => item.key === metricKey) || detectionMetrics[0];
    const request = run && isReplay ? `/runs/${encodeURIComponent(run.id)}/sensitivity?factor=${factorKey}` : '';
    useEffect(() => {
        if (!request) return;
        const controller = new AbortController(); let alive = true;
        setResponse(null);
        api(request, { signal: controller.signal }).then(data => { if (alive) setResponse({ request, data }); })
            .catch(error => { if (alive && error.name !== 'AbortError') setResponse({ request, error: error.message }); });
        return () => { alive = false; controller.abort(); };
    }, [request, retry]);
    const current = response?.request === request ? response : null, data = current?.data;
    const variants = matchedVariants(experiments, run, factor, scenario), baseline = isReplay ? data?.baseline : sensitivityValue(run, factor, scenario);
    const compact = value => value === null || value === undefined ? 'N/A' : String(value).length > 24 ? String(value).slice(0, 16) + '...' : String(value);
    const label = experiments.find(item => item.run.id === run?.id)?.label || 'Selected';
    const levels = data?.levels || [];
    const replayMeasure = (value, arm) => readMeasurement({ config: { arms: (data?.arms || []).join(',') }, utility: (data?.rows || []).filter(r => r.value === value).map(r => ({ ...r, scenario: 'all' })) }, arm, metric);
    return <ChartCard title="Sensitivity Analysis" className="sensitivity-panel"><div className="sensitivity-controls">
        <label className="analysis-field"><span>Parameter</span><select value={factorKey} onChange={e => setFactorKey(e.target.value)}>{sensitivityFactors.map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
        <label className="analysis-field"><span>Outcome</span><select value={metric.key} onChange={e => setMetricKey(e.target.value)}>{options.map(m => <option key={m.key} value={m.key}>{m.label}</option>)}</select></label>
        {factorKey === 'intensity' ? <label className="analysis-field"><span>Scenario</span><select value={scenario} onChange={e => setScenario(e.target.value)}>{attacks.map(a => <option key={a} value={a}>{attackLabels[a]}</option>)}</select></label> :
            <div className="sensitivity-baseline"><span>Baseline from selected experiment</span><strong title={String(baseline ?? '')}>{compact(baseline)}</strong></div>}
    </div>
        {!run ? <Empty /> : isReplay && !data ? <div className="analysis-empty" role={current?.error ? 'alert' : 'status'}>{current?.error || 'Replaying selected events...'}{current?.error && <button onClick={() => setRetry(n => n + 1)}>Retry</button>}</div> :
        <div className="sensitivity-content"><section className="sensitivity-evidence"><h3>{metric.label} by {factor[1].toLowerCase()}</h3>
            {isReplay ? <PythonPlot run={run} kind="sensitivity" factor={factorKey} metric={metric.key} label={label} title="Sensitivity curve" /> : <PythonPlot run={run} kind="sensitivity-variants" factor={factorKey} metric={metric.key} label={label} variants={variants.length ? variants : [{ run, label }]} title="Matched experiment sensitivity" />}
        </section><section className="sensitivity-details"><h3>{metric.label} / Change For Selected Baseline Setting</h3><div className="analysis-table-wrap"><table className="analysis-table sensitivity-table"><thead><tr><th>{isReplay ? 'Setting' : 'Experiment / setting'}</th>{arms.map(arm => <th key={arm} style={{ color: techniqueColors[arm] }}>{arm.toUpperCase()}</th>)}</tr></thead>
            <tbody>{isReplay ? levels.map(level => <tr key={level} className={level === baseline ? 'selected-setting' : ''}><th>{level}{level === baseline && <small>Selected</small>}</th>{arms.map(arm => {
                const m = replayMeasure(level, arm), base = replayMeasure(baseline, arm);
                return <td key={arm} title={measurementText(m)}>{m.value === null ? 'N/A' : percent(m.value)}<Delta value={m.value} baseline={base.value} /></td>;
            })}</tr>) : (variants.length ? variants : [{ run, value: baseline, label: experiments.find(e => e.run.id === run.id)?.label || 'Selected' }]).map(item => <tr key={item.run.id} className={item.run.id === run.id ? 'selected-setting' : ''}><th title={experimentName(item)}>{item.label}<small title={String(item.value)}>{compact(item.value)}</small></th>{arms.map(arm => {
                const m = readMeasurement(item.run, arm, metric), base = readMeasurement(run, arm, metric);
                return <td key={arm} title={measurementText(m)}>{m.value === null ? 'N/A' : percent(m.value)}<Delta value={m.value} baseline={base.value} /></td>;
            })}</tr>)}</tbody></table></div></section></div>}
        <section className="sensitivity-explanation" aria-label="How these results were generated"><h3>Sensitivity Analysis Result Rationale</h3><p>{sensitivityExplanation({ run, label, factor, metric, data, variants, scenario })}</p></section>
    </ChartCard>;
}

const views = ['RESEARCH SUMMARY', 'INCIDENT-LEVEL CORRELATION', 'PRIVACY-CORRELATION', 'CONFUSION MATRIX', 'SENSITIVITY ANALYSIS'];
export default function Analyze({ runs, selected }) {
    const [view, setView] = useState(views[0]), [experimentId, setExperimentId] = useState(selected || '');
    const experiments = analysisExperiments(runs), experiment = experiments.find(item => item.run.id === experimentId) || experiments.find(item => item.run.id === selected) || experiments.at(-1);
    return <div className="analyze-page"><div className="analyze-toolbar"><nav className="analysis-tabs" aria-label="Analyze views">{views.map(name => <button key={name} className={view === name ? 'active' : ''} aria-current={view === name ? 'page' : undefined} onClick={() => setView(name)}>{name}</button>)}</nav>
        <ExperimentSelect experiments={experiments} value={experiment?.run.id} onChange={setExperimentId} /></div>
        <div className="analyze-view" aria-label={view}>
            {view === views[0] && <ResearchSummary run={experiment?.run} />}
            {view === views[1] && <IncidentCorrelation run={experiment?.run} label={experiment?.label} />}
            {view === views[2] && <TradeoffGraph run={experiment?.run} label={experiment?.label} />}
            {view === views[3] && <ConfusionMatrices run={experiment?.run} />}
            {view === views[4] && <SensitivityAnalysis experiments={experiments} run={experiment?.run} />}
        </div>
    </div>;
}
