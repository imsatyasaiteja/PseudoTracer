"""Small, read-only KQL-style filters and streaming release pagination."""
import ast
from collections import deque
import json
import re

ALIASES = {
    'Time': 'time', 'User': 'user.uid', 'IP': 'src_endpoint.ip',
    'Country': 'src_endpoint.location.country', 'Application': 'service.name',
    'Status': 'status', 'MFA': 'is_mfa', 'Risk': 'unmapped.entra.risk_score',
    'RiskLevel': 'unmapped.entra.risk_level_aggregated',
    'EventID': 'metadata.uid', 'SessionID': 'session.uid',
    'Detected': 'alert.detected', 'GroundTruth': 'alert.ground_truth',
    'AlertID': 'alert.id', 'Rule': 'alert.rule', 'Result': 'alert.result',
}
TOKEN = re.compile(r'''\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|>=|<=|==|!=|=~|!~|[()<>]|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)''')


def field_value(event, field):
    for part in field.split('.'):
        event = event.get(part) if isinstance(event, dict) else None
    return event


def compare(actual, operator, expected):
    if actual is None or expected is None:
        return (actual is expected) if operator == '==' else (actual is not expected) if operator == '!=' else False
    if operator in {'contains', 'startswith', '=~', '!~'}:
        left, right = str(actual).casefold(), str(expected).casefold()
        return {'contains': lambda: right in left, 'startswith': lambda: left.startswith(right),
                '=~': lambda: left == right, '!~': lambda: left != right}[operator]()
    if operator in {'==', '!='}:
        equal = type(actual) is type(expected) and actual == expected
        if type(actual) in (int, float) and type(expected) in (int, float):
            equal = actual == expected
        return equal if operator == '==' else not equal
    if type(actual) not in (int, float) or type(expected) not in (int, float):
        return False
    return {'>': lambda: actual > expected, '>=': lambda: actual >= expected,
            '<': lambda: actual < expected, '<=': lambda: actual <= expected}[operator]()


def compile_query(query):
    """Parse comparisons, parentheses and and/or; never execute user code."""
    if len(query) > 2048:
        raise ValueError('Filter is too long (maximum 2048 characters).')
    query = query.strip()
    if not query:
        return lambda event: True
    query = re.sub(r'^(?:(?:Events|Alerts|Incidents)\s*\|\s*)?where\s+', '', query, count=1, flags=re.I)
    tokens, position = [], 0
    while position < len(query):
        match = TOKEN.match(query, position)
        if not match:
            raise ValueError(f'Invalid filter near: {query[position:position + 24]}')
        tokens.append(match[1])
        position = match.end()
    if len(tokens) > 128:
        raise ValueError('Filter is too complex (maximum 128 tokens).')
    index = 0

    def take():
        nonlocal index
        if index >= len(tokens):
            raise ValueError('Incomplete filter. Example: Status == "Failure"')
        token = tokens[index]
        index += 1
        return token

    def expression(level=0):
        nonlocal index
        if level < 2:
            items = [expression(level + 1)]
            keyword = ('or', 'and')[level]
            while index < len(tokens) and tokens[index].lower() == keyword:
                index += 1
                items.append(expression(level + 1))
            return lambda event: (any if level == 0 else all)(item(event) for item in items)
        field = take()
        if field == '(':
            result = expression()
            if take() != ')':
                raise ValueError('Expected a closing parenthesis.')
            return result
        aliases = {name.lower(): path for name, path in ALIASES.items()}
        field = aliases.get(field.lower(), field)
        if not re.fullmatch(r'[a-z_][\w]*(?:\.[a-z_][\w]*)+', field) and field not in {'time', 'status', 'is_mfa'}:
            raise ValueError('Use a supported field alias or a dotted OCSF field path.')
        operator = take().lower()
        if operator not in {'==', '!=', '=~', '!~', '>', '>=', '<', '<=', 'contains', 'startswith'}:
            raise ValueError(f'Unsupported operator: {operator}')
        literal = take()
        if literal[0] in {'"', "'"}:
            try:
                value = ast.literal_eval(literal)
            except (ValueError, SyntaxError):
                raise ValueError('Invalid quoted value.') from None
        elif literal.lower() in {'true', 'false', 'null'}:
            value = {'true': True, 'false': False, 'null': None}[literal.lower()]
        elif re.fullmatch(r'-?\d+(?:\.\d+)?', literal):
            value = float(literal) if '.' in literal else int(literal)
        else:
            raise ValueError('Quote text values; use true, false, null or a number without quotes.')
        return lambda event: compare(field_value(event, field), operator, value)

    predicate = expression()
    if index != len(tokens):
        raise ValueError(f'Unexpected token: {tokens[index]}')
    return predicate


def read_events(path):
    """Stream complete JSONL records, including from an output still being written."""
    if path.exists():
        with path.open(encoding='utf-8') as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    if not line.endswith('\n'):
                        break
                    raise


def paginate_events(records, page=1, query=''):
    if page < 1:
        raise ValueError('Page must be a positive integer.')
    predicate = compile_query(query)
    limit, total, source_total = 300, 0, 0
    events, tail = [], deque(maxlen=limit)
    for event in records:
        source_total += 1
        if predicate(event):
            if (page - 1) * limit <= total < page * limit:
                events.append(event)
            tail.append(event)
            total += 1
    pages = max(1, (total + limit - 1) // limit)
    if page > pages:
        page = pages
        events = list(tail)[-(total % limit or limit):] if total else []
    return {'events': events, 'page': page, 'pages': pages, 'limit': limit,
            'total': total, 'source_total': source_total}


def event_page(path, page=1, query=''):
    return paginate_events(read_events(path), page, query)
