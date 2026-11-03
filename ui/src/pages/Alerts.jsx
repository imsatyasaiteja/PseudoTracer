import React, { Fragment, useId, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { EventExplorer, EventTable, useEventExplorer, attackLabels, display, eventTime } from '../shared';

const summaryMetrics = [
    ['Number of Alerts', 'alerts'],
    ['Users Affected', 'users_affected'],
    ['True Positives', 'true_positives'],
    ['False Positives', 'false_positives'],
    ['False Negatives / Missed Events', 'false_negatives'],
];

export default function Alerts({ run, connected, controls, navigate }) {
    const explorer = useEventExplorer({ run, connected, incidents: true });
    const { arm, data, query, refreshKey } = explorer;
    return <>
        <div className="stats incident-stats">{summaryMetrics.map(([label, field]) =>
            <div className="stat" key={field}>
                <span>{label}</span><strong>{data.summary?.[field]?.toLocaleString() ?? 'N/A'}</strong>
            </div>)}
        </div>
        <EventExplorer explorer={explorer} controls={controls} navigate={navigate}>
            {data.ready && !data.truth_available && <p className="notice">Ground-truth labels are incomplete or unavailable. Unscored totals appear as a dash.</p>}
            <AlertTable key={`${arm}-${data.page}-${query}-${refreshKey}`} alerts={data.alerts} filtered={Boolean(query)} />
        </EventExplorer>
    </>;
}


const ruleLabels = {
    same_ip_many_users: 'Same IP, many users',
    repeated_mfa_denials: 'Repeated MFA denials',
    failures_then_success: 'Failures then success',
    same_user_different_country: 'Same user, different country',
};

function AlertTable({ alerts, filtered }) {
    const [expanded, setExpanded] = useState([]);
    const prefix = useId();
    function toggle(id) {
        setExpanded(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
    }
    return <div className="table-wrap explorer-table" tabIndex={0} role="region" aria-label="IAM Alerts table"><table className="alerts-table">
        <thead><tr>{['Alert', 'Scenario', 'Rule', 'Events', 'Users', 'Time range (local)', 'Result'].map(label =>
            <th key={label} scope="col">{label}</th>)}</tr></thead>
        <tbody>{alerts.map((alert, index) => {
            const open = expanded.includes(alert.incident_id);
            const panelId = `${prefix}-alert-${index}`;
            const Icon = open ? ChevronDown : ChevronRight;
            const resultClass = alert.result === 'True positive' ? 'complete' :
                alert.result === 'False positive' || alert.result === 'Scenario mismatch' ? 'failed' : '';
            return <Fragment key={alert.incident_id}>
                <tr className={'alert-group-row' + (open ? ' expanded' : '')} onClick={() => toggle(alert.incident_id)}>
                    <th scope="row"><button aria-expanded={open} aria-controls={open ? panelId : undefined}
                        aria-label={`${open ? 'Collapse' : 'Expand'} alert ${alert.incident_id}`}
                        onClick={event => { event.stopPropagation(); toggle(alert.incident_id); }}>
                        <Icon size={14} /><code>{alert.incident_id}</code>
                    </button></th>
                    <td>{attackLabels[alert.scenario] || alert.scenario}</td>
                    <td>{ruleLabels[alert.rule] || display(alert.rule)}</td>
                    <td className="alert-count">{display(alert.event_count)}</td>
                    <td className="alert-count">{display(alert.user_count)}</td>
                    <td className="alert-time"><span>{eventTime(alert.start_time)}</span><small>to {eventTime(alert.end_time)}</small></td>
                    <td><span className={'badge ' + resultClass}>{alert.result}</span></td>
                </tr>
                {open && <tr className="alert-members"><td colSpan={7}>
                    <section className="alert-member-content" id={panelId} aria-label={`Events for alert ${alert.incident_id}`}>
                        {(filtered || alert.missing_events > 0) && <div className="alert-member-heading">
                            {filtered && <span>{alert.matched_events} matched the filter; all available members are shown.</span>}
                            {alert.missing_events > 0 && <span>{alert.missing_events} events are not available in the release yet.</span>}
                        </div>}
                        <EventTable events={alert.events} incidents />
                    </section>
                </td></tr>}
            </Fragment>;
        })}</tbody>
    </table></div>;
}
