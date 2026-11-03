import React, { Fragment, useEffect, useId, useState } from 'react';
import { createPortal } from 'react-dom';
import { ArrowUpRight, ChevronLeft, ChevronRight, Search } from 'lucide-react';

// Constants, API, formatting and panels

export const arms = ['raw', 'masked', 'hmac'];
export const attackLabels = {
    password_spray: 'Password spray',
    mfa_fatigue: 'MFA fatigue',
    impossible_travel: 'Impossible travel',
    credential_compromise: 'Credential compromise',
};
export const attacks = Object.keys(attackLabels);

export function runArms(run) {
    return run?.config.arms?.split(',').filter(arm => arms.includes(arm)) || [];
}

export function runAttacks(run) {
    const value = run?.config.attacks;
    if (!value || value === 'none') return [];
    return value === 'all' ? [...attacks] : value.split(',');
}

export function percent(value) {
    if (value === undefined || value === null || value === '') return 'N/A';
    return Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : 'N/A';
}

export async function api(path, options) {
    const response = await fetch('/api' + path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
}

export function download(name, data) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Panel({ title, subtitle, titleAction, action, children, className = '' }) {
    return <section className={'panel ' + className}>
        <div className="panel-heading">
            <div><div className="panel-title"><h2>{title}</h2>{titleAction}</div>{subtitle && <p>{subtitle}</p>}</div>
            {action}
        </div>
        {children}
    </section>;
}

// Run summary

export function RunSummary({ run }) {
    const metrics = [
        ['Baseline events', run ? Number(run.config.events).toLocaleString() : 'N/A'],
        ['Users', run ? number(run.config.users) : 'N/A'],
        ['Devices', run ? number(run.config.devices) : 'N/A'],
        ['IAM Attack Scenarios', run ? runAttacks(run).length : 'N/A'],
        ['Random seed', run ? number(run.config.seed) : 'N/A'],
    ];
    return <dl className="run-summary" aria-label="Selected experiment summary">
        {metrics.map(([label, value]) => <div key={label}>
            <dt>{label}</dt><dd>{value}</dd>
        </div>)}
    </dl>;
}

// Engine result components

export function number(value, suffix = '') {
    if (value === undefined || value === null || value === '') return 'N/A';
    return Number.isFinite(Number(value)) ? Number(value).toLocaleString() + suffix : 'N/A';
}

export function hasCount(value) {
    return value !== '' && value !== null && value !== undefined && Number.isFinite(Number(value));
}

export function rateWithCounts(value, numerator, denominator, label = '') {
    if (!hasCount(numerator) || !hasCount(denominator)) return <span className="rate-value" title={label}>{percent(value)}</span>;
    const rate = Number(denominator) === 0 ? 'N/A' : percent(hasCount(value) ? value : Number(numerator) / Number(denominator));
    return <span className="rate-value" title={label}>{rate} <span className="rate-count">({number(numerator)} / {number(denominator)})</span></span>;
}

export function MetricCard({ title, hint, field, rows, techniques, format = percent, renderValue, className = '' }) {
    return <div className={'result-metric ' + className}>
        <div className="metric-heading"><h3>{title}</h3><p>{hint}</p></div>
        <dl>{techniques.map(arm => <div key={arm}>
            <dt><i className={arm} />{arm.toUpperCase()}</dt>
            <dd>{renderValue ? renderValue(rows.find(row => row.arm === arm) || {}) : format(rows.find(row => row.arm === arm)?.[field])}</dd>
        </div>)}</dl>
    </div>;
}

export function ResultsTable({ title, techniques, rows, metrics }) {
    return <div className="table-wrap results-table"><table aria-label={title}>
        <thead><tr><th scope="col">Metric</th>{techniques.map(arm =>
            <th scope="col" key={arm}><span className="technique-heading"><i className={arm} />{arm.toUpperCase()}</span></th>
        )}</tr></thead>
        <tbody>{metrics.map(([label, render]) => <tr key={label}>
            <th scope="row">{label}</th>
            {techniques.map(arm => <td key={arm}>{render(rows.find(row => row.arm === arm) || {})}</td>)}
        </tr>)}</tbody>
    </table></div>;
}

// Engine empty and progress states

export function EmptyEngine({ pending, navigate }) {
    return <section className="panel welcome">
        <h2>{pending ? 'Starting experiment…' : 'Run an experiment to explore the results'}</h2>
        <p>Generate sign-ins and known IAM attacks and compare correlation and privacy measurements</p>
        <button onClick={() => navigate('Guide')}>Read the guide <ArrowUpRight size={15} /></button>
    </section>;
}

export function RunStatus({ run }) {
    if (run.status === 'complete') return null;
    return <p className="notice" role="status">{run.status === 'failed'
        ? `Experiment failed. ${run.error || 'Results below may be incomplete.'}`
        : 'Results are partial until the experiment completes.'}</p>;
}

// Event field formatting and details

export function display(value) {
    if (value === null || value === undefined || value === '') return 'N/A';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (Array.isArray(value)) return value.length ? value.map(display).join(', ') : 'None';
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

export function eventTime(value) {
    if (value === null || value === undefined || value === '') return 'N/A';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? display(value) : date.toLocaleString();
}

export function mfaResult(event) {
    const steps = event.unmapped?.entra?.authentication_details;
    const mfa = Array.isArray(steps) ? steps.filter(step => step.authenticationMethod &&
        step.authenticationMethod.toLowerCase() !== 'password') : [];
    if (!mfa.length) return event.is_mfa === false ? 'Not required' : 'Not recorded';
    return mfa.map(step => `${step.authenticationMethod}: ${step.succeeded === true ? 'Success' :
        step.succeeded === false ? 'Failure' : 'Not recorded'}`).join('; ');
}

export function eventSections(event) {
    const source = event.src_endpoint || {};
    const entra = event.unmapped?.entra || {};
    return {
        'Event Identity': [
            ['Event ID', event.metadata?.uid], ['Event type', event.type_name || event.class_name],
            ['Event time (local)', eventTime(event.time)], ['Original source time', event.metadata?.original_time],
            ['Correlation ID', event.metadata?.correlation_uid], ['Session ID', event.session?.uid],
        ],
        'User and Device': [
            ['User identifier', event.user?.uid], ['User name', event.user?.name], ['Email', event.user?.email_addr],
            ['Device identifier', source.uid], ['Device name', source.name], ['Device type', entra.device_type],
            ['Operating system', source.os?.version || source.os?.name], ['Browser', entra.device_browser],
            ['User agent', entra.user_agent],
        ],
        Authentication: [
            ['Sign-in status', event.status], ['Status code', event.status_code], ['Status detail', event.status_detail],
            ['MFA required', event.is_mfa], ['MFA result', mfaResult(event)],
            ['Authentication protocol', event.auth_protocol], ['Logon type', event.logon_type],
        ],
        'Network and Location': [
            ['Source IP', source.ip], ['Country', source.location?.country],
            ['Remote/local status', event.is_remote === true ? 'Remote' : event.is_remote === false ? 'Local' : null],
            ['RTT (ms)', entra.round_trip_time_ms],
        ],
        'Risk and Application': [
            ['Risk score', entra.risk_score], ['Risk level', entra.risk_level_aggregated],
            ['Risk state', entra.risk_state], ['Risk event types', entra.risk_events],
            ['Application name', event.service?.name], ['Service ID', event.service?.uid],
            ['Conditional-access status', entra.conditional_access_status],
        ],
    };
}

// Event response validation

export function validateEventPage(data, collection = 'events') {
    if (collection === 'alerts' && Array.isArray(data?.events) && !Array.isArray(data.alerts)) {
        throw new Error('The alerts API needs restarting. Run python ui/server.py again, then select Retry.');
    }
    if (Array.isArray(data?.events) && data.page === undefined && data.total === undefined) {
        throw new Error('The event API needs restarting. Stop the Python adapter, run python ui/server.py again, then select Retry.');
    }
    const counts = ['page', 'pages', 'total', 'source_total', 'limit'];
    const rows = data?.[collection];
    if (!data || !Array.isArray(rows) ||
        counts.some(key => !Number.isSafeInteger(data[key])) ||
        data.page < 1 || data.pages < 1 || data.page > data.pages ||
        data.total < 0 || data.source_total < data.total || data.limit !== 300 ||
        data.pages !== Math.max(1, Math.ceil(data.total / data.limit)) ||
        rows.length !== Math.min(data.limit, Math.max(0, data.total - (data.page - 1) * data.limit)) ||
        rows.some(event => !event || typeof event !== 'object' || Array.isArray(event)) ||
        (collection === 'alerts' && rows.some(alert => !Array.isArray(alert.events) || !alert.incident_id))) {
        throw new Error('The event API returned an invalid page. Retry to load the events again.');
    }
    return data;
}

// Event fetching and pagination state

const emptyPage = { events: [], alerts: [], page: 1, pages: 1, total: 0, source_total: 0 };

export function useEventExplorer({ run, connected, incidents = false }) {
    const [preferredArm, setPreferredArm] = useState('hmac');
    const [data, setData] = useState(emptyPage);
    const [draft, setDraft] = useState('');
    const [query, setQuery] = useState('');
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [refreshKey, setRefreshKey] = useState(0);
    const availableArms = runArms(run);
    const arm = availableArms.includes(preferredArm) ? preferredArm : availableArms[0];

    useEffect(() => {
        const controller = new AbortController();
        let timer;
        setData(emptyPage);
        setError('');
        setLoading(Boolean(run && arm && connected));
        async function load() {
            try {
                const params = new URLSearchParams({ arm, page, q: query });
                const response = await api(`/runs/${run.id}/${incidents ? 'incidents' : 'events'}?${params}`, { signal: controller.signal });
                const result = validateEventPage(response, incidents ? 'alerts' : 'events');
                if (!controller.signal.aborted) {
                    setData(result);
                    setError('');
                    if (result.page !== page) setPage(result.page);
                }
            } catch (error) {
                if (!controller.signal.aborted) setError(incidents && error.message === 'Not found'
                    ? 'The alerts API is unavailable. Restart python ui/server.py, then select Retry.' : error.message);
            } finally {
                if (!controller.signal.aborted) {
                    setLoading(false);
                    if (run.status === 'running') timer = setTimeout(load, 2500);
                }
            }
        }
        if (run && arm && connected) load();
        return () => { controller.abort(); clearTimeout(timer); };
    }, [run?.id, run?.status, arm, connected, page, query, refreshKey, incidents]);

    const records = incidents ? data.alerts : data.events;
    const start = data.total ? (data.page - 1) * 300 + 1 : 0;
    const end = data.total ? start + records.length - 1 : 0;
    const disabled = loading || !connected || !run || Boolean(error);
    return { run, connected, incidents, data, arm, availableArms, loading, error, query, draft,
        page, start, end, records, disabled, refreshKey, setPage, setPreferredArm, setDraft, setQuery, setRefreshKey };
}

// Event explorer controls

export function EventExplorer({ explorer, controls, navigate, children }) {
    const { run, connected, incidents, data, arm, availableArms, loading, error, query, draft,
        start, end, records, disabled, setPage, setPreferredArm, setDraft, setQuery, setRefreshKey } = explorer;
    const pagination = <div className="event-pagination" aria-label="Event pagination">
        <span aria-live="polite">{loading ? 'Loading...' : `${start.toLocaleString()}-${end.toLocaleString()} of ${data.total.toLocaleString()} ${incidents ? 'alerts' : 'events'}`}</span>
        <button aria-label="Previous event page" disabled={disabled || data.page <= 1} onClick={() => setPage(data.page - 1)}><ChevronLeft size={15} /></button>
        <label>Page <select aria-label="Event page" disabled={disabled || !data.total} value={data.page}
            onChange={event => setPage(Number(event.target.value))}>
            {Array.from({ length: data.pages }, (_, index) => <option key={index + 1} value={index + 1}>{index + 1}</option>)}
        </select> of {data.pages}</label>
        <button aria-label="Next event page" disabled={disabled || data.page >= data.pages} onClick={() => setPage(data.page + 1)}><ChevronRight size={15} /></button>
    </div>;

    const techniques = <div className="segmented" aria-label="Privacy Technique">{availableArms.map(item => <button key={item}
        aria-pressed={arm === item} className={arm === item ? 'selected' : ''}
        onClick={() => { setPreferredArm(item); setPage(1); }}>{item.toUpperCase()}</button>)}</div>;

    return <>
        {controls ? createPortal(techniques, controls) : techniques}
        <Panel className="event-explorer-panel" title={incidents ? 'IAM Alerts' : 'IAM Events'} titleAction={
            <button className="syntax-guide" onClick={() => navigate('Guide')}>Filter Syntax Guide</button>
        } action={pagination}>
            <form className="event-filter" onSubmit={event => { event.preventDefault(); setPage(1); setQuery(draft.trim()); }}>
                <div className="query-input"><Search size={17} />
                    <input aria-label={incidents ? 'KQL-style alert filter' : 'KQL-style event filter'} value={draft}
                        placeholder={incidents ? 'Alerts | where Detected contains "password_spray"' : 'Events | where Sign-In Status == "Failure" and Risk >= 50'} onChange={event => setDraft(event.target.value)} />
                </div>
                <button className="primary" disabled={!run || !connected || loading} type="submit">Apply filter</button>
                <button type="button" disabled={!draft && !query} onClick={() => { setDraft(''); setQuery(''); setPage(1); }}>Clear</button>
            </form>
            {query && !loading && !error && <p className="filter-help">Filtered across all {data.source_total.toLocaleString()} {incidents ? 'alerts' : 'released events'}.</p>}
            {error && <div className="notice error" role="alert"><span>{error}</span>
                <button disabled={loading || !connected} onClick={() => setRefreshKey(value => value + 1)}>Retry</button>
            </div>}
            <div className="explorer-body">
            {children}
            {!records.length && !error && <div className="empty">{loading ? 'Loading events...' : !run ? 'Select or create an experiment.' : !connected ? 'Connect the engine to load events.' : query ? (incidents ? 'No alerts match this filter.' : 'No events match this filter.') : incidents ? (data.ready ? 'No alerts were produced for this privacy technique.' : 'Correlation output is not available yet.') : 'No released events available yet.'}</div>}
            </div>
        </Panel>
    </>;
}

// JSON display

// Render tokens as text, so values from telemetry cannot inject HTML.
export function JsonCode({ value }) {
    const json = JSON.stringify(value, (_, item) => item === undefined ? null : item, 2);
    const tokens = json.split(/("(?:\\.|[^"\\])*"\s*:|"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?|[{}\[\]])/gi);
    return <pre className="json-code"><code>{tokens.map((token, index) => {
        const type = token.startsWith('"') ? (token.trimEnd().endsWith(':') ? 'key' : 'string')
            : /^(true|false|null)$/.test(token) ? 'literal'
                : /^-?\d/.test(token) ? 'number' : /^[{}\[\]]$/.test(token) ? 'bracket' : '';
        return <span key={index} className={type ? `json-${type}` : undefined}>{token}</span>;
    })}</code></pre>;
}

// Event table and inspector

function EventDetail({ event, id }) {
    const [section, setSection] = useState('Event Identity');
    const sections = eventSections(event);
    if (event.alert) sections['Event Identity'] = [...sections['Event Identity'],
        ['Detected', event.alert.detected], ['Ground truth', event.alert.ground_truth], ['Matching alerts', event.alert.matches]];
    return <div className="event-inspector" id={id}>
        <div className="detail-categories" role="group" aria-label="Event detail categories">
            {Object.keys(sections).map(name => <button key={name} aria-pressed={section === name}
                onClick={() => setSection(name)}>{name}</button>)}
        </div>
        <section className="detail-content" aria-label={section}>
            <h3>{section}</h3>
            <JsonCode value={Object.fromEntries(sections[section])} />
        </section>
    </div>;
}

export function EventTable({ events, incidents = false, start = 1 }) {
    const [expanded, setExpanded] = useState(null);
    const prefix = useId();
    return <div className="table-wrap explorer-table" tabIndex={0} role="region" aria-label="IAM Events table"><table className="events-table">
        <thead><tr>{['Time (local)', 'User', 'IP', 'Country', 'Application', 'Sign-In Status',
            ...(incidents ? ['Detected', 'Ground Truth'] : []), 'Detail'].map(label =>
            <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody>{events.map((row, index) => {
            const id = row.metadata?.uid || `${prefix}-${index}`;
            const open = expanded === id;
            const detailId = `${prefix}-event-detail-${index}`;
            return <Fragment key={id}>
                <tr className={'event-data-row' + (open ? ' event-row-expanded' : '')}>
                    <td>{eventTime(row.time)}</td><td className="mono" title={display(row.user?.uid)}>{display(row.user?.uid)}</td>
                    <td className="mono" title={display(row.src_endpoint?.ip)}>{display(row.src_endpoint?.ip)}</td>
                    <td>{display(row.src_endpoint?.location?.country)}</td><td>{display(row.service?.name)}</td>
                    <td><span className={'badge ' + (row.status === 'Success' ? 'complete' : row.status === 'Failure' ? 'failed' : '')}>{display(row.status)}</span></td>
                    {incidents && <>
                        <td className="alert-labels">{row.alert?.detected?.split(', ').map(name => <span key={name}>{attackLabels[name] || name}</span>)}</td>
                        <td className="alert-labels">{attackLabels[row.alert?.ground_truth] || (row.alert?.ground_truth === 'normal_background' ? 'Normal background' : display(row.alert?.ground_truth))}</td>
                    </>}
                    <td><button aria-expanded={open} aria-controls={open ? detailId : undefined}
                        aria-label={`${open ? 'Hide' : 'View'} event ${start + index} details`}
                        onClick={() => setExpanded(open ? null : id)}>{open ? 'Hide' : 'View'}</button></td>
                </tr>
                {open && <tr className="event-detail-row"><td colSpan={incidents ? 9 : 7}>
                    <EventDetail event={row} id={detailId} />
                </td></tr>}
            </Fragment>;
        })}</tbody>
    </table></div>;
}
