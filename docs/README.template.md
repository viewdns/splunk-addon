# ViewDNS Add-on for Splunk (TA-viewdns)

Enrich Splunk searches, alerts and investigations with [ViewDNS.info](https://viewdns.info) DNS, IP and WHOIS
intelligence: WHOIS, reverse IP, IP history, DNS records, subdomains, reverse WHOIS, reverse NS/MX, abuse contacts,
IP location, reverse DNS, spam blacklists, DNSSEC, free email and MAC lookups, plus live checks (port scan, ping,
traceroute, HTTP headers, DNS propagation, China and Iran firewall tests).

This is an **enrichment** add-on: it looks values up on demand. It does not ingest data on a schedule.

- **Search command** `| viewdns action=<lookup> field=<field>`: adds `viewdns_*` fields to your events.
- **Alert action / ES adaptive response** "ViewDNS Enrichment": writes lookup results to an index as
  `sourcetype=viewdns:enrichment`.
- **Dashboard** "ViewDNS Investigate": enter a domain, IP, email or MAC address and see everything about it.
- **Credit protection**: a KV store cache, dedupe within each search, a per-search lookup cap, and a results cap.

Version 1.0.0 · Splunk Enterprise 9.3+ and 10.x · Splunk Cloud (Victoria and Classic) · Python 3.9 and 3.13 ·
Support: support@viewdns.info · Source and issues: <https://github.com/viewdns/splunk-addon>

---

## Contents

1. [Requirements](#requirements)
2. [Install](#install)
3. [Configure](#configure)
4. [Permissions](#permissions)
5. [The `viewdns` search command](#the-viewdns-search-command)
6. [Lookup reference](#lookup-reference)
7. [Alert action and Enterprise Security](#alert-action-and-enterprise-security)
8. [The viewdns:enrichment sourcetype](#the-viewdnsenrichment-sourcetype)
9. [ViewDNS Investigate dashboard](#viewdns-investigate-dashboard)
10. [API credits: how much does it cost?](#api-credits-how-much-does-it-cost)
11. [Errors and troubleshooting](#errors-and-troubleshooting)
12. [Splunk Cloud](#splunk-cloud)
13. [Security notes](#security-notes)
14. [Uninstall](#uninstall)

---

## Requirements

- A ViewDNS.info API key (<https://viewdns.info/api/>). WHOIS and Reverse WHOIS require a paid plan; with a free
  key those lookups return a clear "requires a paid ViewDNS API plan" error.
- Splunk Enterprise 9.3 or later (Python 3.9 or 3.13; tested on 9.4 and 10.6), or Splunk Cloud.
- Outbound HTTPS (port 443) from the search head(s) to `api.viewdns.info`, directly or through an HTTP proxy.

Install the add-on on **search heads only**. It has no inputs and nothing for indexers or forwarders to do. In a
search head cluster, deploy it with the deployer.

## Install

**From Splunkbase:** in Splunk Web, open **Apps → Find More Apps**, search for "ViewDNS" and click **Install**.

**From a file:** **Apps → Manage Apps → Install app from file**, choose `TA-viewdns-<version>.tar.gz`, then restart
Splunk if asked.

**Command line:**

```
$SPLUNK_HOME/bin/splunk install app TA-viewdns-1.0.0.tar.gz -auth admin:<password>
$SPLUNK_HOME/bin/splunk restart
```

## Configure

Open **Apps → ViewDNS Add-on for Splunk → Configuration**.

**ViewDNS Settings tab**

| Setting | Default | Description |
|---|---|---|
| API key | — | Your ViewDNS API key. Stored encrypted in Splunk's credential store (never in a .conf file). When you save, it is checked against the free ViewDNS account API. |
| Base URL | `https://api.viewdns.info` | Must be HTTPS. |
| Request timeout (seconds) | 100 | How long to wait for a ViewDNS response. Large reverse lookups can take close to a minute. A request that times out is **not retried**, because ViewDNS may already have counted the query. |
| Max results per lookup | 100 | The most results kept for one value (for example domains on a reverse IP). The command's `limit=` cannot exceed it. 1–10,000. |
| Max API lookups per search | 1000 | Credit guard: the most uncached API calls a single search or alert can make. Further values are skipped with a warning. |
| Cache TTL (seconds) | 86400 | How long results are cached in the KV store. `0` disables the cache. Live checks and spam blacklist lookups are cached for at most 1 hour regardless. |

**Proxy tab:** enable, host, port, username and password (stored encrypted). HTTP proxies (CONNECT) are supported.
If you need a proxy, save it before the API key so the key check can get through.

**Logging tab:** log level for `$SPLUNK_HOME/var/log/splunk/ta_viewdns.log` (searchable in `index=_internal
source=*ta_viewdns.log`). The API key is never logged.

To check the setup, run `| viewdnsaccount`. It shows your plan, monthly usage and prepaid balance, and costs no
query.

## Permissions

Running lookups requires the **`viewdns_lookup`** capability. The add-on provides:

- the **`viewdns_user`** role (inherits `user`, adds `viewdns_lookup`). Assign it to analysts.
- `viewdns_lookup` for the `admin` role.

In Splunk Cloud, an `sc_admin` assigns `viewdns_user` to users or roles, or adds the `viewdns_lookup` capability to an
existing role.

`viewdns_lookup` does **not** let users read the API key or any other stored credential. Searches call a REST
endpoint inside the add-on (`/services/ta_viewdns/lookup`), which reads the key with Splunk's system credentials,
calls ViewDNS and returns only the results. Users without the capability see: *"ViewDNS: your Splunk role is not
allowed to run ViewDNS lookups. Ask an admin to give you the viewdns_user role (or the viewdns_lookup capability)."*

The alert action runs as the alert's owner, so the owner needs `viewdns_lookup` too.

## The `viewdns` search command

```
| viewdns action=<lookup> field=<field>
          [recordtype=<type>] [limit=<n>] [output=mv|rows] [cache=true|false] [prefix=<string>]
```

| Argument | Default | Description |
|---|---|---|
| `action` | (required) | The lookup to run. See the [lookup reference](#lookup-reference). |
| `field` | (required) | The field holding the values to look up. Multivalue fields are supported: every value is looked up. |
| `recordtype` | `ANY` | `action=dnsrecord` only: `ANY`, `A`, `AAAA`, `CAA`, `CNAME`, `DNSKEY`, `DS`, `MX`, `NS`, `NSEC`, `PTR`, `RRSIG`, `SOA`, `SRV` or `TXT`. |
| `limit` | Max results per lookup | The most results kept per value. Values above the configured maximum are capped with a warning. |
| `output` | `mv` | `mv`: one event out per event in, results in multivalue fields. `rows`: one event per result (the original fields are copied to each). |
| `cache` | `true` | `false` skips reading the cache (fresh results are still written to it). |
| `prefix` | `viewdns_` | Prefix of the output fields. Use a different prefix to chain lookups without overwriting earlier results. |

### Examples

```
index=proxy | stats count by dest_ip | viewdns action=reverseip field=dest_ip
```
Other domains hosted on each destination IP.

```
| makeresults | eval domain="example.com" | viewdns action=iphistory field=domain output=rows
```
One row per historical IP address.

```
index=email | stats count by src_domain | viewdns action=dnsrecord field=src_domain recordtype=MX
```
MX records of each sender domain.

```
| makeresults | eval domain="example.com"
| viewdns action=iphistory field=domain output=rows
| viewdns action=whois field=viewdns_ip prefix=ipwhois_
| table viewdns_ip viewdns_last_seen ipwhois_owner ipwhois_asn ipwhois_country
```
Chained lookups: WHOIS of every IP the domain has used.

```
index=firewall | stats count by src_ip
| viewdns action=iplocation field=src_ip
| viewdns action=spamdblookup field=src_ip prefix=spam_
| table src_ip count viewdns_country_name viewdns_city spam_blacklisted_count
```
Location and spam blacklist status of each source IP.

```
index=dhcp | stats count by src_mac | viewdns action=maclookup field=src_mac
```
Manufacturer of each MAC address.

```
| makeresults | eval domain="example.com" | viewdns action=subdomains field=domain output=rows
```
Known subdomains and their current IPs.

```
| makeresults | eval host="example.com" | viewdns action=portscan field=host output=rows | where viewdns_port_status="open"
```
Open ports (a live check: ViewDNS scans the host).

> **Tip:** run the command after `stats ... by <field>` (or `dedup`) where you can. The command dedupes values within a
> search anyway, but fewer events make the search faster.

### Fields added to every event

| Field | Description |
|---|---|
| `viewdns_action` | The lookup that ran. |
| `viewdns_query` | The normalized value that was looked up (lowercased; URLs reduced to their host; MACs to hex digits). |
| `viewdns_status` | `ok`, `no_results`, `error`, `skipped` (field empty or missing) or `skipped_quota_guard` (credit guard reached). |
| `viewdns_error` | The error message when `viewdns_status=error`. |
| `viewdns_cached` | `1` if the result came from the cache (no query used). |
| `viewdns_result_count` | Results attached to this event. |
| `viewdns_total_count` | Total results ViewDNS has for the value (may be larger than what is returned). |
| `viewdns_truncated` | `1` if there were more results than were returned. |

With a multivalue input field, these fields are multivalue too, in the same order as `viewdns_query`. Use
`output=rows` when you need to know which input value each result belongs to.

In `output=mv` mode, the per-result fields of one-to-many lookups are **parallel multivalue fields**: the n-th value
of `viewdns_domain` belongs with the n-th value of `viewdns_last_resolved`. Missing values are kept as empty strings so
the positions stay aligned. For subdomains, each subdomain's IPs are one space-separated value of
`viewdns_subdomain_ips`; with `output=rows` they are a multivalue field.

## Lookup reference

{{ACTIONS_TABLE}}

\* *summary field: one value per looked-up value (shown once in `mv` mode, repeated on every row in `rows` mode).*

**Live checks** make ViewDNS servers contact the target at the time of the lookup: port scan, ping, traceroute,
HTTP headers, DNS propagation and the firewall tests. Use them deliberately; the target will see traffic from
ViewDNS (not from you).

Notes on specific lookups:

- **whois** works for both domains and IPs. `viewdns_whois_type` tells you which (`domain` or `ip`). Contact fields
  reading "REDACTED FOR PRIVACY" are dropped. Requires a paid plan.
- **reversewhois** searches by email address, registrant name or organization (at least 5 characters). Requires a
  paid plan; free keys get an error instead of ViewDNS's demonstration data.
- **reverseip, reversens, reversemx and reversewhois** return at most 10,000 (reverse WHOIS: 1,000) results per
  lookup; `viewdns_total_count` shows the full count.
- **iphistory** only tracks registered domains, not subdomains.
- **subdomains**: ViewDNS reduces any host to its registered domain (`mail.example.co.uk` → `example.co.uk`).
- **freeemail** accepts an email address and checks its domain.
- **iranfirewall** accepts a domain or an http(s) URL; bare domains are tested as `http://<domain>`.

## Alert action and Enterprise Security

Add **ViewDNS Enrichment** as a trigger action on any alert (in Enterprise Security it is also available as an
Adaptive Response action, including ad hoc from a notable event).

| Parameter | Default | Description |
|---|---|---|
| Lookup | WHOIS | Any of the 22 lookups. |
| Field | `dest` | The field in the triggering results to look up. Multivalue fields are split. |
| DNS record type | ANY | For the DNS records lookup. |
| Max results per value | (configured maximum) | |
| Max values per alert | 100 | Only the first N distinct values are looked up. The per-search credit guard also applies. |
| Index | `summary` | Where the results are written. The index must exist. |

Each distinct value becomes one event in the chosen index with `sourcetype=viewdns:enrichment`, carrying
`search_name`, `orig_sid` and `orig_rid` (the result it came from), so you can trace it back to the alert. The action's
success or failure is recorded in the standard modular action logs, which Enterprise Security shows in the adaptive
response status.

Find the results with:

```
index=summary sourcetype="viewdns:enrichment" search_name="<your alert>"
```

Enrichment events count against your Splunk license like any other indexed data (they are small: one event per
looked-up value).

## The viewdns:enrichment sourcetype

Events are JSON. Fields are extracted automatically (`KV_MODE=json`), and list results are exposed under their plain
names (for example `domain` rather than `domain{}`).

| Field | Description |
|---|---|
| `lookup` | The lookup (named `lookup` rather than `action`, because `action` has a different meaning in the CIM). |
| `field`, `query` | The alert field and the value looked up. |
| `status`, `error`, `cached`, `result_count`, `total_count`, `truncated` | As for the search command. |
| result fields | The lookup's fields from the [lookup reference](#lookup-reference), without the `viewdns_` prefix. |
| `search_name`, `orig_sid`, `orig_rid`, `orig_action_name` | Where the event came from. |
| `vendor_product` | `ViewDNS.info` |

CIM-friendly fields:

| Field | Set for |
|---|---|
| `dest` | The looked-up domain or IP (all lookups except reversewhois, freeemail and maclookup). |
| `dest_ip` | iphistory (the historical IPs); whois, iplocation, reversedns and spamdblookup of an IP. |
| `dest_mac` | maclookup. |
| `dest_port` | portscan. |
| `src_user` | reversewhois (the search term). |
| `answer` | dnsrecord (the record data). |
| `domain`, `created`, `updated`, `expires`, `registrar`, `nameservers` | whois of a domain (names used by Enterprise Security's domain analysis). |

Events are tagged `viewdns` and `enrichment` (eventtype `viewdns_enrichment`) and `modaction_result` (eventtype
`viewdns_enrichment_modaction_result`, used by Enterprise Security). They are deliberately not tagged for any CIM data
model, so they don't mix into your DNS or network traffic data.

## ViewDNS Investigate dashboard

The add-on's home page. Enter a domain, IP address, email address or MAC address and click **Submit**. The
dashboard detects the type and shows:

| Input | Panels | Queries for a new value |
|---|---|---|
| Domain | WHOIS; domain facts (abuse contact, DNSSEC, free email provider); IP history; DNS records; subdomains; reverse IP | 8 |
| IP address | WHOIS; IP facts (location, reverse DNS, abuse contact); spam blacklists; reverse IP | 6 |
| Email address | free email provider check; reverse WHOIS | 2 |
| MAC address | manufacturer | 1 |
| Live checks (tick the box; domains and IPs) | port scan; HTTP headers; traceroute | +3 |

Click a domain, IP, name server or registrant email in a table to investigate it next. The top of the dashboard shows
your remaining API queries and prepaid balance, and the bottom lists any alert enrichment events for the value.
Repeat lookups come from the cache and cost nothing.

The app menu also has **Cache → Cached lookups**, which lists what is in the cache and when each entry expires.

## API credits: how much does it cost?

Each **uncached lookup of one value is one ViewDNS API query**. Pagination is never used, so a lookup is always a
single query however many results it returns.

What doesn't use queries:

- values already looked up within the same search (deduplicated);
- values in the cache (24 hours by default; live checks and spam blacklists 1 hour);
- empty or invalid values (rejected before calling ViewDNS);
- `| viewdnsaccount` and the API key check when you save the configuration.

Safeguards:

- **Max API lookups per search** (default 1000) stops a search such as `index=* | viewdns ...` from spending
  thousands of queries. Further values get `viewdns_status=skipped_quota_guard` and the search shows a warning.
- **Max results per lookup** (default 100) caps the size of each result.
- The alert action looks up at most **Max values per alert** (default 100) distinct values.
- A request that times out is not retried (ViewDNS may already have counted it). When the query quota is used up
  (HTTP 429), the add-on stops calling the API for the rest of the search instead of retrying.

The cache holds results, not the API key, and is shared by all users of the add-on.

## Errors and troubleshooting

| Message | What to do |
|---|---|
| *the add-on is not configured yet* / *no API key is configured* | Save your API key on the Configuration page. |
| *the API key is invalid* | Check the key. The add-on stops calling the API for the rest of the search. |
| *the API query quota is used up* | Your monthly limit is reached and no prepaid queries remain. Check `\| viewdnsaccount`. |
| *this lookup requires a paid ViewDNS API plan* | WHOIS and Reverse WHOIS need a paid key. Other lookups keep working. |
| *your Splunk role is not allowed to run ViewDNS lookups* | Ask an admin for the `viewdns_user` role. |
| *'x' is not a valid ... for <lookup>* | The value doesn't fit the lookup (for example a domain for `iplocation`). No query is used. |
| *the credit guard stopped lookups after N API calls* | Narrow the search, or raise Max API lookups per search. |
| *no response within N seconds* | Raise the request timeout (large reverse lookups can take close to a minute). |
| *could not connect to the API* / *stopped after 5 consecutive network failures* | Check outbound access to api.viewdns.info:443 and the proxy settings. |

Errors appear as search messages, never as stack traces. On Splunk 10.x, errors that stop all lookups (bad key, no
quota, no permission) end the search with the message. On 9.x, the search continues and the events carry
`viewdns_status=error`. Per-value problems are warnings, and the affected events carry `viewdns_status=error` and
`viewdns_error`.

Logs: `index=_internal source=*ta_viewdns.log`. Set the level to DEBUG on the Logging tab for more detail.

## Splunk Cloud

The add-on passes Splunk AppInspect including the Splunk Cloud checks, and supports Victoria and Classic Experience.

1. Install it from Splunkbase (or, for a private build, upload it as a private app).
2. Make sure the search heads can reach `https://api.viewdns.info` (port 443). If outbound connections from your
   stack are restricted, ask Splunk Support to allow `api.viewdns.info`, or configure an HTTP proxy on the Proxy tab.
   Saving the API key on the Configuration page tests the connection.
3. Configure the API key, then give analysts the `viewdns_user` role (as `sc_admin`).
4. The alert action writes to the `summary` index by default; choose another index if you prefer.

## Security notes

- The API key and proxy password are stored in Splunk's encrypted credential store and are read only by the add-on's
  lookup endpoint, with system credentials. They never appear in .conf files, search results, the cache, or logs, and
  are removed from any error message.
- Users need only the `viewdns_lookup` capability, not `list_storage_passwords`.
- Only admins and the add-on's endpoint can write the cache, so users cannot plant fake results in it.
- All API traffic uses HTTPS with certificate verification.
- Live checks cause ViewDNS servers to send traffic to the target host.

## Uninstall

Remove `$SPLUNK_HOME/etc/apps/TA-viewdns` (or uninstall it from **Manage Apps** in Splunk Cloud) and restart. The
stored API key lives in the add-on's own `local/passwords.conf` and is removed with it. To empty the cache first, run
`| outputlookup viewdns_cache_lookup` with no input as an admin. Enrichment events already written to your indexes are not removed.

## Third-party software

The add-on bundles splunk-sdk, solnlib, splunktaucclib, requests, urllib3, certifi, idna, charset-normalizer,
defusedxml, sortedcontainers, PySocks and packaging, each under its own license (see `lib/*.dist-info`). The add-on
itself is licensed under the Apache License 2.0 (`LICENSES/Apache-2.0.txt`).
