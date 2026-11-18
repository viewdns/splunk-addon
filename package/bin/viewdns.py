#!/usr/bin/env python
"""``viewdns`` custom streaming search command: enriches events with ViewDNS.info lookups.

    | viewdns action=<abuselookup|chinesefirewall|dnsrecord|dnssec|freeemail|httpheaders|iphistory|iplocation|iranfirewall|maclookup|ping|portscan|propagation|reversedns|reverseip|reversemx|reversens|reversewhois|spamdblookup|subdomains|traceroute|whois> field=<field>
              [recordtype=ANY] [limit=<n>] [output=mv|rows] [cache=true|false] [prefix=viewdns_]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, Option, StreamingCommand, dispatch, validators  # noqa: E402

from ta_viewdns import remote, splunk_env  # noqa: E402
from ta_viewdns.actions import ACTION_NAMES, DNS_RECORD_TYPES  # noqa: E402
from ta_viewdns.enrich import STATUS_ERROR, Outcome  # noqa: E402
from ta_viewdns.output import enrich_mv, enrich_rows, values_of  # noqa: E402

logger = splunk_env.setup_logging()


@Configuration(distributed=False)
class ViewDNSCommand(StreamingCommand):
    """
    ##Syntax
    | viewdns action=<abuselookup|chinesefirewall|dnsrecord|dnssec|freeemail|httpheaders|iphistory|iplocation|iranfirewall|maclookup|ping|portscan|propagation|reversedns|reverseip|reversemx|reversens|reversewhois|spamdblookup|subdomains|traceroute|whois> field=<field> [recordtype=<type>] [limit=<int>] [output=mv|rows] [cache=<bool>]
      [prefix=<string>]

    ##Description
    Looks up each value of <field> with the ViewDNS.info API and adds the results to the event as <prefix>* fields.
    Lookups are deduplicated within the search and cached in the KV store, so a value costs at most one API query
    per cache TTL.
    """

    action = Option(
        doc="The lookup: abuselookup, chinesefirewall, dnsrecord, dnssec, freeemail, httpheaders, iphistory, iplocation, iranfirewall, maclookup, ping, portscan, propagation, reversedns, reverseip, reversemx, reversens, reversewhois, spamdblookup, subdomains, traceroute, whois.",
        require=True,
        validate=validators.Match("action", r"^[A-Za-z]+$"),
    )
    field = Option(doc="The field holding the values to look up.", require=True, validate=validators.Fieldname())
    recordtype = Option(
        doc="DNS record type for action=dnsrecord. Default ANY.",
        require=False,
        default="ANY",
        validate=validators.Match("recordtype", r"^[A-Za-z]{1,10}$"),
    )
    limit = Option(
        doc="Most results kept per value. Default and maximum: Max results per lookup on the Configuration page.",
        require=False,
        validate=validators.Integer(minimum=1),
    )
    output = Option(
        doc="mv (default): one event with multivalue fields. rows: one event per result.",
        require=False,
        default="mv",
        validate=validators.Set("mv", "rows"),
    )
    cache = Option(
        doc="false skips reading the KV store cache (results are still written). Default true.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    prefix = Option(
        doc="Prefix for output fields. Default viewdns_. Change it to chain several viewdns commands.",
        require=False,
        default="viewdns_",
        validate=validators.Match("prefix", r"^[A-Za-z_][A-Za-z0-9_]{0,30}$"),
    )

    def __init__(self):
        super(ViewDNSCommand, self).__init__()
        self._resolver = None
        self._limit_warned = False
        self._action = None
        self._recordtype = "ANY"

    # -- setup -------------------------------------------------------------------------------------------------------

    def prepare(self):
        self._action = str(self.action).lower()
        if self._action not in ACTION_NAMES:
            self.write_error("ViewDNS: action must be one of: {0}.".format(", ".join(ACTION_NAMES)))
            sys.exit(1)
        self._recordtype = str(self.recordtype or "ANY").upper()
        if self._recordtype not in DNS_RECORD_TYPES:
            self.write_error("ViewDNS: recordtype must be one of: {0}.".format(", ".join(DNS_RECORD_TYPES)))
            sys.exit(1)
        if self._recordtype != "ANY" and self._action != "dnsrecord":
            self.write_warning("ViewDNS: recordtype is only used by action=dnsrecord and was ignored.")
            self._recordtype = "ANY"

    def _setup(self):
        """Connects to the add-on's lookup endpoint on the first chunk, with the user's own session.

        The command never reads the API key: the endpoint (capability viewdns_lookup) does the lookups.
        """
        if self._resolver is not None:
            return
        info = self._metadata.searchinfo
        service = remote.connect_user_service(info.session_key, info.splunkd_uri)
        self._resolver = remote.RemoteResolver(remote.splunk_transport(service))
        logger.info(
            "viewdns search sid=%s user=%s action=%s field=%s output=%s limit=%s python=%s",
            info.sid, info.username, self._action, self.field, self.output, self.limit, sys.version.split()[0],
        )

    def _effective_limit(self):
        max_results = self._resolver.max_results
        if max_results is None:
            return int(self.limit) if self.limit is not None else None
        if self.limit is not None and int(self.limit) > max_results and not self._limit_warned:
            self._limit_warned = True
            self.write_warning(
                "ViewDNS: limit={0} is above Max results per lookup ({1}); using {1}.".format(self.limit, max_results)
            )
        return min(int(self.limit), max_results) if self.limit is not None else max_results

    # -- streaming ---------------------------------------------------------------------------------------------------

    def stream(self, records):
        self._setup()
        records = list(records)
        per_record = [values_of(record, self.field) for record in records]
        all_values = [value for values in per_record for value in values]
        try:
            outcomes = self._resolver.resolve(self._action, all_values, self._recordtype, use_cache=self.cache)
        except Exception as error:  # never show a stack trace
            logger.exception("ViewDNS lookup failed")
            self.write_error("ViewDNS: lookup failed ({0}).".format(type(error).__name__))
            outcomes = {}
        self._flush_messages()
        limit = self._effective_limit()
        logger.debug(
            "viewdns chunk sid=%s records=%d totals: api_calls=%d cache_hits=%d memo_entries=%d",
            self._metadata.searchinfo.sid, len(records), self._resolver.api_calls,
            self._resolver.cache_hits, len(self._resolver.memo),
        )

        enrich = enrich_rows if self.output == "rows" else enrich_mv
        error_text = self._resolver.fatal or "ViewDNS: lookup failed."
        for record, values in zip(records, per_record):
            record_outcomes = []
            for value in values:
                outcome = outcomes.get(value)
                if outcome is None:
                    outcome = Outcome(str(value).strip(), STATUS_ERROR, error=error_text)
                record_outcomes.append(outcome)
            for output in enrich(record, self._action, record_outcomes, self.prefix, limit):
                yield output

    def _flush_messages(self):
        for level, text in self._resolver.drain_messages():
            text = text.replace("{prefix}", self.prefix)
            if level == "error":
                self.write_error(text)
            else:
                self.write_warning(text)


if __name__ == "__main__":
    dispatch(ViewDNSCommand, sys.argv, sys.stdin, sys.stdout, __name__)
