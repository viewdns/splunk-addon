# encoding = utf-8
"""ViewDNS Enrichment alert action / Enterprise Security adaptive response action.

Looks up one field of the triggering results with ViewDNS (through the add-on's lookup endpoint, so the alert owner
needs the viewdns_lookup capability) and writes one JSON event per distinct value to the chosen index with
sourcetype viewdns:enrichment.
"""

import json
import logging
import time

from ta_viewdns import remote
from ta_viewdns.actions import ACTION_NAMES, ACTIONS, DNS_RECORD_TYPES
from ta_viewdns.enrich import STATUS_NO_RESULTS, STATUS_OK

SOURCETYPE = "viewdns:enrichment"
SPOOL_EXTENSION = "viewdns_enrichment"  # matches [source::...stash_viewdns_enrichment] in props.conf
DEFAULT_MAX_VALUES = 100
HARD_MAX_VALUES = 10000

# Whois returns one record; only these of its fields are lists.
WHOIS_LIST_FIELDS = ("nameserver", "domain_status")


def result_values(result, field):
    """A field's values from a results-file row. Multivalue fields arrive encoded as ``$a$;$b$`` in __mv_<field>."""
    encoded = result.get("__mv_" + field)
    if encoded:
        values = [part.replace("$$", "$") for part in encoded[1:-1].split("$;$")]
    else:
        raw = result.get(field)
        values = raw.split("\n") if raw else []
    return [value.strip() for value in values if value and value.strip()]


def _int_param(helper, name, default, low, high):
    value = helper.get_param(name)
    if value in (None, ""):
        return default
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValueError("'{0}' must be a whole number, got {1!r}".format(name, value))
    return max(low, min(high, number))


def build_event(action_name, field, outcome, limit, context):
    """One flat JSON event for a looked-up value. Result fields are always lists for one-to-many lookups."""
    action = ACTIONS[action_name]
    rows, truncated = outcome.limited(limit)
    event = {
        "time": round(time.time(), 3),
        "lookup": action_name,
        "field": field,
        "query": outcome.query,
        "status": outcome.status,
        "cached": 1 if outcome.cached else 0,
        "result_count": len(rows),
        "truncated": 1 if truncated else 0,
        "vendor_product": "ViewDNS.info",
    }
    if outcome.status in (STATUS_OK, STATUS_NO_RESULTS):
        event["total_count"] = outcome.total_count
    if outcome.error:
        event["error"] = outcome.error
    if action.one_to_many:
        for name in action.summary_fields:
            if rows and rows[0].get(name) not in (None, ""):
                event[name] = rows[0][name]
        for name in action.fields:
            if name in action.summary_fields:
                continue
            values = [row.get(name) for row in rows]
            # Lists inside a result (subdomain_ips) become one space-separated string, keeping arrays flat.
            values = [" ".join(str(item) for item in value) if isinstance(value, list) else value for value in values]
            if any(value not in (None, "") for value in values):
                event[name] = ["" if value is None else value for value in values]
    elif rows:
        for name, value in rows[0].items():
            if name in WHOIS_LIST_FIELDS and not isinstance(value, list):
                value = [value]
            event[name] = value
    event.update({key: value for key, value in context.items() if value})
    return event


def process_event(helper, *args, **kwargs):
    action_name = str(helper.get_param("lookup_action") or "").strip().lower()
    field = str(helper.get_param("field") or "").strip()
    recordtype = str(helper.get_param("recordtype") or "ANY").strip().upper()
    index = str(helper.get_param("index") or "summary").strip()
    if action_name not in ACTION_NAMES:
        helper.log_error("Invalid lookup {0!r}; expected one of {1}.".format(action_name, ", ".join(ACTION_NAMES)))
        return 3
    if recordtype not in DNS_RECORD_TYPES:
        helper.log_error("Invalid DNS record type {0!r}.".format(recordtype))
        return 3
    try:
        limit = _int_param(helper, "limit", None, 1, 10000)
        max_values = _int_param(helper, "max_values", DEFAULT_MAX_VALUES, 1, HARD_MAX_VALUES)
    except ValueError as error:
        helper.log_error(str(error))
        return 3

    # Distinct values in result order, remembering the first result each came from (for orig_rid).
    first_result = {}
    order = []
    skipped = 0
    for result in helper.get_events():
        for value in result_values(result, field):
            if value in first_result:
                continue
            if len(order) >= max_values:
                skipped += 1
                continue
            first_result[value] = dict(result)
            order.append(value)
    if not order:
        helper.log_info("No values in field {0!r} of the triggering results; nothing to look up.".format(field))
        return 0
    if skipped:
        helper.log_warn(
            "Looked up the first {0} distinct values of {1!r}; {2} more were skipped (Max values per alert)."
            .format(max_values, field, skipped)
        )

    service = remote.connect_user_service(helper.session_key, helper.settings["server_uri"])
    resolver = remote.RemoteResolver(remote.splunk_transport(service))
    outcomes = resolver.resolve(action_name, order, recordtype, use_cache=True)
    for level, text in resolver.drain_messages():
        text = text.replace("{prefix}", "")
        (helper.log_error if level == "error" else helper.log_warn)(text)
    effective_limit = min(limit, resolver.max_results) if (limit and resolver.max_results) else (
        limit or resolver.max_results
    )

    counts = {}
    for value in order:
        outcome = outcomes[value]
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
        helper.update(first_result[value])  # sets rid / orig_rid for this event
        context = {
            "search_name": helper.search_name,
            "orig_action_name": helper.action_name,
            "orig_sid": helper.orig_sid or helper.sid,
            "orig_rid": helper.orig_rid or helper.rid,
        }
        event = build_event(action_name, field, outcome, effective_limit, context)
        helper.addevent(json.dumps(event, sort_keys=False, separators=(",", ":")), sourcetype=SOURCETYPE, cam_header=False)

    written = helper.writeevents(index=index, source="viewdns_enrichment", fext=SPOOL_EXTENSION)
    summary = "ViewDNS {0}: {1} values, statuses {2}, api_calls={3}, cache_hits={4}, index={5}".format(
        action_name, len(order), counts, resolver.api_calls, resolver.cache_hits, index
    )
    if resolver.fatal:
        helper.message(summary + "; error: " + resolver.fatal, status="failure", level=logging.ERROR)
        return 2
    helper.message(summary, status="success" if written else "failure")
    return 0 if written else 2
