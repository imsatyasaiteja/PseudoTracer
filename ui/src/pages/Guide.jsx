import React, { useEffect, useState } from 'react';
import { ArrowUpRight } from 'lucide-react';
import { api, Panel } from '../shared';

export default function Guide({ navigate, run, connected }) {
    return <div className="guide">
        <section className="panel explainer query-guide">
            <h2>Filter Syntax Guide</h2>
            <p>Choose an experiment and privacy technique in Events, enter a filter and select Apply filter.
                Filtering covers the full release. Pages show 300 matches each; Clear restores all events.</p>
            <pre>{'Events | where Status == "Failure"\nEvents | where Risk >= 50 and MFA == true\nEvents | where Country == "US" or Country == "SG"\nEvents | where Application contains "office"\nEvents | where (Status == "Failure" or Risk >= 70) and MFA == true\nEvents | where user.email_addr contains "@contoso"'}</pre>
            <p><code>Events | where</code> and <code>where</code> are optional prefixes.
                Use <code>==</code> / <code>!=</code> for exact comparisons,
                <code> =~</code> / <code>!~</code> for case-insensitive equality,
                and <code>contains</code> / <code>startswith</code> for case-insensitive text matching.
                Numeric comparisons support <code>{'>, >=, <, <='}</code>.</p>
            <p>Combine conditions with <code>and</code>, <code>or</code> and parentheses.
                Without parentheses, <code>and</code> takes priority. Quote text values;
                numbers, <code>true</code>, <code>false</code> and <code>null</code> are unquoted.</p>
            <p>Aliases: <code>Time, User, IP, Country, Application, Status, MFA, Risk, RiskLevel, EventID, SessionID</code>.
                User means user identifier; MFA means MFA required; Risk means numeric risk score;
                Time is Unix milliseconds. Alias names ignore case. Dotted OCSF paths are case-sensitive.</p>
            <p>This is a focused KQL-style subset: sorting, aggregation, joins and other pipe commands are not supported.
                Missing paths act as null; use <code>user.email_addr != null</code> to find populated fields.
                Filters use released values, so RAW identifiers may not match MASKED or HMAC records.</p>
            <h3>Alerts and IAM Alerts</h3>
            <p>Each Alerts row is a saved alert, with its scenario, rule, event and user counts,
                time range and result. Expand it to inspect its events, then use View for event details.
                Shared events appear under every matching alert. Pages contain up to 300 alerts.
                Switch RAW, MASKED or HMAC to inspect that technique's detections.</p>
            <pre>{'Alerts | where Detected contains "password_spray"\nAlerts | where GroundTruth == "normal_background"\nAlerts | where Detected contains "mfa_fatigue" and Country == "US"'}</pre>
            <p>Filters select alerts with at least one matching member event; expanding a result shows all its events.
                In filters, <code>Detected</code> is the current alert's scenario.
                Use <code>AlertID</code>, <code>Rule</code> and <code>Result</code> to filter alert metadata.
                For example, <code>{'Alerts | where AlertID == "alert_0001"'}</code>.
                Event detail rows still show all matching detections.
                <code>GroundTruth</code> is the saved sidecar scenario label; <code>unknown</code> means no label is available.
                Use scenario names <code>password_spray</code>, <code>mfa_fatigue</code>,
                <code> impossible_travel</code>, <code>credential_compromise</code> and <code>normal_background</code>.
                <code> Alerts | where</code> and <code>Incidents | where</code> are accepted prefixes.</p>
            <p>Number of Alerts counts correlation hypotheses. Users Affected counts distinct source users
                in flagged events using the sidecar, even when masking merges identities.
                True positives and false positives count unique flagged attack and normal events.
                False negatives count attack events absent from all alerts. These counts match the overall event-level
                scoring, so a wrong scenario label can still count as a detected attack event.
                All five totals cover the entire selected technique, independent of filters and pages.</p>
            <p>Alert Result: True positive means all member events are attacks with the detected scenario;
                Mixed means some match and others do not. False positive means all are normal events.
                Scenario mismatch means attack events are present but none match the detected scenario.
                Unknown means labels are missing. Users counts distinct source users from the sidecar.</p>
            <button onClick={() => navigate('Events')}>Open Events <ArrowUpRight size={15} /></button>
        </section>
        <section className="panel explainer">
            <h2>Reading the measurements</h2>
            <dl className="metric-definitions">
                <dt>Precision</dt><dd>How many flagged events were actually attack events.</dd>
                <dt>Recall</dt><dd>How many attack events were recovered.</dd>
                <dt>F1</dt><dd>A balance of precision and recall; not a guarantee of full incident detection.</dd>
                <dt>Direct exposure</dt><dd>Source identifier values found anywhere in the release.</dd>
                <dt>Profile linkage</dt><dd>User matches from location and application patterns. Coverage shows how many released identities were tested.</dd>
                <dt>Composite linkage</dt><dd>Successful user matches from combined clues. Read the attempt counts in the export.</dd>
                <dt>Snapshot linkage</dt><dd>Users linked across time windows, measured among users present in both windows.</dd>
            </dl>
        </section>
        <PrivacyPolicy run={run} connected={connected} />
        <section className="panel explainer">
            <h2>Start with one controlled experiment</h2>
            <button className="primary" onClick={() => navigate('New Experiment')}>Create experiment <ArrowUpRight size={15} /></button>
        </section>
    </div>;
}

function PrivacyPolicy({ run, connected }) {
    const [policy, setPolicy] = useState(null);
    const [error, setError] = useState('');

    useEffect(() => {
        let active = true;
        setPolicy(null);
        setError('');
        if (connected) api(run ? `/runs/${run.id}/policy` : '/policy')
            .then(data => { if (active) setPolicy(data); })
            .catch(error => { if (active) setError(error.message); });
        return () => { active = false; };
    }, [run?.id, run?.status, connected]);

    return <Panel title="Privacy Policy" subtitle="Field transformations across privacy techniques." action={<span className="pill">READ ONLY</span>}>
        {policy && <p className="policy-note">{policy.source === 'snapshot'
            ? `Policy saved with ${run.id}. Unlisted fields are retained.`
            : run ? `No policy snapshot for ${run.id}. Showing the current policy; it may differ from the policy used.`
                : 'Current policy for new experiments. Unlisted fields are retained.'}</p>}
        {error && <div className="notice error" role="alert">{error}</div>}
        <div className="table-wrap"><table>
            <thead><tr><th>OCSF field</th><th>Classification</th><th>RAW</th><th>MASKED</th><th>HMAC</th></tr></thead>
            <tbody>{Object.entries(policy?.fields || {}).map(([field, rule]) => <tr key={field}>
                <td className="mono">{field}</td><td>{rule.class?.replaceAll('_', ' ')}</td><td className="muted">Retain</td>
                <td className={rule.masked ? 'teal' : 'muted'}>{rule.masked || 'Retain'}</td>
                <td className={rule.hmac ? 'lavender' : 'muted'}>{rule.hmac || 'Retain'}</td>
            </tr>)}</tbody>
        </table></div>
        {!policy && !error && <div className="empty">{connected ? 'Loading policy…' : 'Connect the engine to read the policy.'}</div>}
    </Panel>;
}
