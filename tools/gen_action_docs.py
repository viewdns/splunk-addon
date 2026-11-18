"""Prints the Markdown reference table of lookups from the action registry (dev tool, not shipped)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "package", "bin"))
from ta_viewdns.actions import ACTIONS  # noqa: E402

ORDER = [
    "whois", "reverseip", "iphistory", "dnsrecord", "subdomains", "reversewhois", "reversens", "reversemx",
    "abuselookup", "iplocation", "reversedns", "spamdblookup", "dnssec", "freeemail", "maclookup",
    "httpheaders", "portscan", "traceroute", "ping", "propagation", "chinesefirewall", "iranfirewall",
]
assert set(ORDER) == set(ACTIONS), set(ACTIONS) ^ set(ORDER)
print("| `action=` | Lookup | Input | Output fields (after the `viewdns_` prefix) | Results | Cached for |")
print("|---|---|---|---|---|---|")
for name in ORDER:
    action = ACTIONS[name]
    fields = ", ".join("`{0}`{1}".format(f, "*" if f in action.summary_fields else "") for f in action.fields)
    shape = "one per value" if not action.one_to_many else "many per value"
    ttl = "≤ 1 hour" if action.max_cache_ttl else "cache TTL"
    label = action.label + (" (live)" if action.live else "")
    print("| `{0}` | {1} | {2} | {3} | {4} | {5} |".format(name, label, action.input_label, fields, shape, ttl))
