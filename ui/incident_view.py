"""Join saved alerts to released events and scoring labels for the local lab UI.

Truth is used only here for evaluation; it is never passed to the detector.
"""
from collections import defaultdict

from event_query import compile_query, paginate_events, read_events


def alert_result(alert, truth):
    labels = [truth.get(event_id) for event_id in set(alert['event_ids'])]
    if not labels or any(label is None for label in labels):
        return 'Unknown'
    correct = sum(bool(label.get('is_attack')) and label.get('scenario') == alert['scenario'] for label in labels)
    if correct == len(labels):
        return 'True positive'
    if correct:
        return 'Mixed'
    return 'Scenario mismatch' if any(label.get('is_attack') for label in labels) else 'False positive'


def incident_page(run, arm, page=1, query=''):
    alerts_path = run / 'correlated' / f'{arm}_{run.name}_incidents.jsonl'
    release_path = run / 'releases' / f'{arm}_{run.name}.jsonl'
    truth_path = run / 'ground_truth' / 'truth.jsonl'
    # Present legacy detector IDs as alert IDs consistently in rows, details and filters.
    # Saved experiment artifacts keep their original identifiers.
    alerts = [{**alert, 'incident_id': 'alert_' + alert['incident_id'][4:]
               if alert['incident_id'].startswith('det_') else alert['incident_id']}
              for alert in read_events(alerts_path)]
    truth = {row['event_id']: row for row in read_events(truth_path)}
    by_event = defaultdict(list)
    for alert in alerts:
        for event_id in set(alert['event_ids']):
            by_event[event_id].append(alert)
    flagged = set(by_event)
    attacks = {event_id for event_id, row in truth.items() if row.get('is_attack')}
    has_truth = truth_path.exists() and flagged <= truth.keys()
    ready = alerts_path.exists() and release_path.exists()
    users = {truth[event_id].get('true_user_id') for event_id in flagged if event_id in truth}
    users_known = has_truth and None not in users and '' not in users
    summary = {
        'alerts': len(alerts) if ready else None,
        'users_affected': len(users) if ready and users_known else None,
        'true_positives': len(flagged & attacks) if ready and has_truth else None,
        'false_positives': len(flagged - attacks) if ready and has_truth else None,
        'false_negatives': len(attacks - flagged) if ready and has_truth else None,
    }

    def suspicious_events():
        for event in read_events(release_path):
            event_id = event.get('metadata', {}).get('uid')
            matches = by_event.get(event_id)
            if matches:
                label = truth.get(event_id)
                yield {**event, 'alert': {
                    'detected': ', '.join(sorted({alert['scenario'] for alert in matches})),
                    'ground_truth': label.get('scenario', 'unknown') if label else 'unknown',
                    'matches': [{'incident_id': alert['incident_id'], 'scenario': alert['scenario'],
                                 'rule': alert.get('rule'), 'detected_at': alert.get('detected_at')}
                                for alert in matches],
                }}

    events = {event['metadata']['uid']: event for event in suspicious_events()}
    predicate = compile_query(query)

    def groups():
        for alert in alerts:
            event_ids = list(dict.fromkeys(alert['event_ids']))
            members = [events[event_id] for event_id in event_ids if event_id in events]
            result = alert_result(alert, truth)
            context = {'detected': alert['scenario'], 'id': alert['incident_id'],
                       'rule': alert.get('rule'), 'result': result}
            # A filter selects whole alerts; keep all members when expanding one.
            matched = sum(predicate({**event, 'alert': {**event['alert'], **context}}) for event in members)
            if query and not matched and (members or not predicate({'alert': context})):
                continue
            member_users = {truth.get(event_id, {}).get('true_user_id') for event_id in event_ids}
            users_known = truth_path.exists() and None not in member_users and '' not in member_users
            yield {
                'incident_id': alert['incident_id'], 'scenario': alert['scenario'],
                'rule': alert.get('rule'), 'start_time': alert.get('start_time'),
                'end_time': alert.get('end_time'), 'detected_at': alert.get('detected_at'),
                'event_count': len(event_ids), 'user_count': len(member_users) if users_known else None,
                'result': result, 'events': members, 'matched_events': matched,
                'missing_events': len(event_ids) - len(members),
            }

    response = paginate_events(groups(), page)
    response['alerts'] = response.pop('events')
    response['source_total'] = len(alerts)
    return {**response, 'summary': summary, 'ready': ready, 'truth_available': has_truth}
