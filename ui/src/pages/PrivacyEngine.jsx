import React from 'react';
import { percent, rateWithCounts, runArms, MetricCard, ResultsTable, number, EmptyEngine, RunStatus } from '../shared';

export function countRatio(correct, total, emptyLabel, rate) {
    if ([correct, total].some(value => value === '' || value === undefined || value === null || !Number.isFinite(Number(value)))) {
        return percent(rate);
    }
    return Number(total) === 0 ? emptyLabel : `${number(correct)} / ${number(total)}`;
}

export default function PrivacyEngine({ run, pending, navigate }) {
    if (!run) return <EmptyEngine pending={pending} navigate={navigate} />;
    const techniques = runArms(run);
    const privacy = run.privacy;
    const privacyAttacks = [
        ['Frequency inference', 'frequency_inference_risk', 'frequency_correct', 'frequency_attempts'],
        ['Profile linkage', 'auxiliary_linkage_success', 'auxiliary_correct', 'auxiliary_attempts'],
        ['Composite linkage', 'composite_auxiliary_linkage_success', 'composite_auxiliary_correct', 'composite_auxiliary_attempts'],
        ['Cross-snapshot linkage (users)', 'cross_snapshot_linkability', 'snapshot_linked_users', 'snapshot_eligible_users'],
    ];

    return <>
        <RunStatus run={run} />
        <div className="engine-results privacy-results">
            <div className="result-pages">
            <section className="result-page" aria-label="Privacy measurements">
            <div className="result-grid privacy-overview">
                <MetricCard title="Identifier Leakage" hint="Disclosed source field/value pairs / All distinct source field/value pairs"
                    rows={privacy} techniques={techniques} className="exposure-card"
                    renderValue={row => <span className="count-value">{countRatio(row.direct_identifiers_disclosed, row.direct_identifiers_total, 'No source identifiers', row.direct_identifier_leakage)}</span>} />
                <MetricCard title="Re-identification Success" hint="Correct identity guesses / All guesses across three identity attacks"
                    rows={privacy} techniques={techniques} className="reidentification-card"
                    renderValue={row => <span className="count-value">{countRatio(row.reidentification_correct, row.reidentification_attempts, 'No identity guesses', row.reidentification_success_rate)}</span>} />
                <section className="result-table-card privacy-attacks">
                    <div className="result-section-heading"><h2>Privacy Attack Techniques</h2><p>*Lower is better</p></div>
                    <ResultsTable title="Privacy Attack Techniques" techniques={techniques} rows={privacy}
                        metrics={privacyAttacks.map(([title, field, correct, total]) => [title,
                            row => rateWithCounts(row[field], row[correct], row[total], field === 'cross_snapshot_linkability'
                                ? 'Linked users / Users present in both time windows' : 'Correct identity guesses / Evaluated guesses')])} />
                </section>
            <section className="result-table-card residual-risk">
                <div className="result-section-heading"><h2>Residual Identification Risk</h2><p>*Lower is better</p></div>
                <ResultsTable title="Residual Identification Risk" techniques={techniques} rows={privacy} metrics={[
                    ['Unique Event Signatures', row => rateWithCounts(row.residual_uniqueness, row.residual_unique_events, row.residual_total_events)],
                    ['Composite Signatures Tied to One User', row => rateWithCounts(row.composite_signature_uniqueness, row.composite_unique_signatures, row.composite_total_signatures)],
                    ['Users With a Unique Composite Signature', row => rateWithCounts(row.composite_unique_user_rate, row.composite_unique_users, row.composite_total_users)],
                ]} />
            </section>
            </div>
            </section>
            </div>
            {!privacy.length && <p className="empty">Privacy measurements will appear when scoring finishes.</p>}
        </div>
    </>;
}
