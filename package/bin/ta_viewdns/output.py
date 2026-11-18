"""Turns lookup outcomes into Splunk records (``output=mv`` or ``output=rows``)."""

from .actions import ACTIONS

META_FIELDS = ("action", "query", "status", "error", "cached", "result_count", "total_count", "truncated")


def field_names(action_name, prefix):
    """Every output field for the action, in a stable order.

    splunklib takes a chunk's column list from its first record, so every record must carry every field.
    """
    return [prefix + name for name in META_FIELDS] + [prefix + name for name in ACTIONS[action_name].fields]


def _collapse(values):
    """[] -> None, [x] -> x, [x, y] -> [x, y] (multivalue)."""
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return values


def _meta(action_name, outcome, limit):
    rows, truncated = outcome.limited(limit)
    return rows, {
        "action": action_name,
        "query": outcome.query or None,
        "status": outcome.status,
        "error": outcome.error,
        "cached": 1 if outcome.cached else 0,
        "result_count": len(rows),
        "total_count": outcome.total_count if outcome.status in ("ok", "no_results") else None,
        "truncated": 1 if truncated else 0,
    }


def _blank(record, names):
    for name in names:
        record[name] = None
    return record


def values_of(record, field):
    """A field's values as a list (multivalue fields arrive as lists)."""
    value = record.get(field)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if item not in (None, "")]
    return [value] if value != "" else []


def enrich_mv(record, action_name, outcomes, prefix, limit):
    """One output record per input record. With several input values, meta fields are multivalue and aligned with
    ``<prefix>query``; result fields are concatenated in input order."""
    action = ACTIONS[action_name]
    _blank(record, field_names(action_name, prefix))
    if not outcomes:
        record[prefix + "action"] = action_name
        record[prefix + "status"] = "skipped"
        record[prefix + "cached"] = 0
        record[prefix + "result_count"] = 0
        record[prefix + "truncated"] = 0
        return [record]
    metas = {name: [] for name in META_FIELDS}
    results = {name: [] for name in action.fields}
    for outcome in outcomes:
        rows, meta = _meta(action_name, outcome, limit)
        for name in META_FIELDS:
            metas[name].append("" if meta[name] is None else meta[name])
        # Summary fields (one value per lookup, repeated on each row by the parser) are taken once per value.
        for name in action.summary_fields:
            value = rows[0].get(name) if rows else None
            results[name].append("" if value is None else value)
        for row in rows:
            for name in action.fields:
                if name in action.summary_fields:
                    continue
                value = row.get(name)
                if isinstance(value, list) and action.one_to_many:
                    # One cell per result keeps parallel fields aligned (e.g. subdomain_ips).
                    results[name].append(" ".join(str(item) for item in value))
                elif isinstance(value, list):
                    results[name].extend(value)
                elif action.one_to_many:
                    # Keep parallel fields aligned: same position = same result.
                    results[name].append("" if value is None else value)
                elif value is not None:
                    results[name].append(value)
    for name in META_FIELDS:
        values = metas[name]
        if name == "action":
            values = [action_name]
        if all(value == "" for value in values):
            values = []
        record[prefix + name] = _collapse(values)
    for name in action.fields:
        values = results[name]
        if all(value == "" for value in values):
            values = []
        record[prefix + name] = _collapse(values)
    return [record]


def enrich_rows(record, action_name, outcomes, prefix, limit):
    """One output record per result; values with no results produce one record carrying only the meta fields."""
    action = ACTIONS[action_name]
    names = field_names(action_name, prefix)
    if not outcomes:
        return enrich_mv(record, action_name, outcomes, prefix, limit)
    output = []
    for outcome in outcomes:
        rows, meta = _meta(action_name, outcome, limit)
        for row in rows or [None]:
            new = _blank(dict(record), names)
            for name in META_FIELDS:
                new[prefix + name] = meta[name]
            if row:
                for name in action.fields:
                    value = row.get(name)
                    new[prefix + name] = _collapse(value) if isinstance(value, list) else value
            output.append(new)
    return output
