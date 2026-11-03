import React from 'react';
import { hasCount, rateWithCounts, runArms, runAttacks, MetricCard, number, EmptyEngine, RunStatus } from '../shared';

export default function CorrelationEngine({ run, pending, navigate }) {
    if (!run) return <EmptyEngine pending={pending} navigate={navigate} />;
    const techniques = runArms(run);
    const utility = run.utility.filter(row => row.scenario === 'all');
    const correlationMetrics = [
        ['False-positive Rate', 'False Positives / All normal events', 'false_positive_rate',
            row => rateWithCounts(row.false_positive_rate, row.false_positive_events, row.normal_events)],
        ['F1 Score', '(2 * True Positives) / (Flagged events + Attack events)', 'f1',
            row => rateWithCounts(row.f1,
                hasCount(row.true_positive_events) ? 2 * Number(row.true_positive_events) : null,
                hasCount(row.predicted_events) && hasCount(row.attack_events) ? Number(row.predicted_events) + Number(row.attack_events) : null)],
        ['Precision', 'True Positives / All flagged events', 'precision',
            row => rateWithCounts(row.precision, row.true_positive_events, row.predicted_events)],
        ['Recall', 'True Positives / Ground-truth attack events', 'recall',
            row => rateWithCounts(row.recall, row.true_positive_events, row.attack_events)],
        ['Pairwise Entity Link Accuracy', 'Same-user pairs / Evaluated pairs in user-linked alerts', 'entity_link_accuracy',
            row => rateWithCounts(row.entity_link_accuracy, row.entity_link_correct_pairs, row.entity_link_total_pairs)],
    ];

    return <>
        <RunStatus run={run} />
        {!runAttacks(run).length && <p className="notice">Control run: no IAM attack scenarios selected. Focus on false positives.</p>}
        <div className="engine-results correlation-results">
            <div className="result-pages">
            <section className="result-page" aria-label="Correlation measurements">
            <div className="result-grid quality-grid correlation-metrics">
                {correlationMetrics.map(([title, hint, field, renderValue]) =>
                    <MetricCard key={field} {...{ title, hint, field, renderValue, techniques }} rows={utility} />)}
                <MetricCard title="Mean Detection Time" hint="Seconds to detection, averaged over detected incidents only; lower is better"
                    field="mean_time_to_detect_seconds" rows={utility} techniques={techniques} className="detection-time-card"
                    format={value => number(value, ' s')} />
            </div>
            </section>
            </div>
            {!utility.length && <p className="empty">Correlation measurements will appear when scoring finishes.</p>}
        </div>
    </>;
}
