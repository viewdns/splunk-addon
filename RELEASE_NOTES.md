# Release notes: ViewDNS Add-on for Splunk

## 1.0.0 (2026-11)

First release.

**Search commands**

- `| viewdns action=<lookup> field=<field>` enriches events with any of 22 ViewDNS.info lookups:
  - WHOIS, reverse IP, IP history, DNS records, subdomains, reverse WHOIS, reverse NS and reverse MX;
  - abuse contact, IP location, reverse DNS, spam blacklists, DNSSEC, free email and MAC lookup;
  - live checks: HTTP headers, port scan, traceroute, ping, DNS propagation, and the China and Iran firewall tests.
- Output as multivalue fields (`output=mv`) or one event per result (`output=rows`).
- Multivalue input fields are supported, and `prefix=` lets you chain lookups.
- `| viewdnsaccount` shows the API plan, usage and prepaid balance. It uses no query.

**Credit protection**

- KV store cache (default 24 hours; live checks and spam blacklists at most 1 hour).
- Dedupe of repeated values within a search.
- Per-search cap on API lookups (default 1000) and a results cap per lookup (default 100).
- Invalid values are rejected before any query.

**Alert action / Enterprise Security adaptive response**

- "ViewDNS Enrichment" writes one `viewdns:enrichment` event per distinct value to an index of your choice.
- Events carry `orig_sid`/`orig_rid`/`search_name` and ES `modaction_result` tagging.

**Sourcetype** `viewdns:enrichment` with JSON field extraction and CIM-friendly fields (`dest`, `dest_ip`,
`dest_mac`, `dest_port`, `src_user`, `answer`, and WHOIS `created`/`updated`/`expires`/`registrar`/`nameservers`).

**Dashboard** "ViewDNS Investigate" for domains, IPs, email addresses and MAC addresses, with click-to-pivot,
opt-in live checks and remaining-credit tiles.

**Security**

- The API key is stored encrypted and read only by the add-on's own REST endpoint.
- Users need just the `viewdns_lookup` capability (role `viewdns_user`), not `list_storage_passwords`.
- The key never appears in logs or error messages.

**Robustness**

- Clear search messages for a bad key, used-up quota, a paid-plan-only lookup, invalid input, network problems and
  missing permissions.
- Retries with backoff on 5xx and connection errors. 429 (quota used up) and read timeouts are not retried, so no
  query is charged twice.

**Compatibility:** Splunk Enterprise 9.3+ and 10.x (tested on 9.4 with Python 3.9 and 10.6 with Python 3.13), and
Splunk Cloud (Victoria and Classic). Passes Splunk AppInspect including the Splunk Cloud checks.
