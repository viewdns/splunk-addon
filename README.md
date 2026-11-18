# TA-viewdns: ViewDNS Add-on for Splunk (source)

Source for the **ViewDNS Add-on for Splunk**. It enriches Splunk searches, alerts and Enterprise Security
investigations with the ViewDNS.info API: 22 lookups, a `viewdns` search command, an alert/adaptive response action,
a `viewdns:enrichment` sourcetype and the "ViewDNS Investigate" dashboard.

- **User guide** (install, configuration, command syntax and examples, lookup reference, credit usage, Splunk Cloud):
  [`package/README.md`](package/README.md). It ships inside the add-on.
- **Release notes:** [`RELEASE_NOTES.md`](RELEASE_NOTES.md)

## Quick start (local test in Docker)

Requires Docker with Compose v2 and Python 3.9+.

```bash
python3 -m venv .venv
.venv/bin/pip install splunk-add-on-ucc-framework==6.6.1 splunk-sdk==2.1.1 requests pytest pytest-cov splunk-appinspect

scripts/build.sh                  # -> dist/TA-viewdns-1.0.0.tar.gz
cp .env.example .env              # set SPLUNK_PASSWORD (and VIEWDNS_API_KEY for the smoke test)
docker compose up -d              # Splunk 9.4 with the add-on installed; first start takes 3-5 minutes
docker compose ps                 # wait until STATUS shows (healthy)
```

Then:

1. Open <http://localhost:8000> and log in as `admin` with `SPLUNK_PASSWORD` from `.env`. On Windows with WSL2,
   `localhost` works from the Windows browser too.
2. Go to **Apps → ViewDNS Add-on for Splunk → Configuration** and save your ViewDNS API key.
3. Try the **ViewDNS Investigate** dashboard (the app's home page) or a search:
   ```
   | makeresults | eval ip="8.8.8.8" | viewdns action=reverseip field=ip limit=5
   | viewdnsaccount
   ```
4. To test as a non-admin, create a user with the `viewdns_user` role (**Settings → Users**). A user with only the
   `user` role gets the "not allowed to run ViewDNS lookups" message.

**Splunk 10.6 (Python 3.13)** as a second instance on <http://localhost:18000> (REST on 18089):

```bash
docker compose --profile splunk10 up -d splunk10
```

**After changing code**, rebuild and reinstall into the running instance(s):

```bash
scripts/build.sh && scripts/reinstall.sh                               # Splunk 9.4
SPLUNK_CONTAINER=viewdns-splunk10 scripts/reinstall.sh                 # Splunk 10.6
```

**Helper scripts** (they run inside the container, so no ports or certificates are involved):

| Script | Purpose |
|---|---|
| `scripts/build.sh [version]` | Build with ucc-gen and package into `dist/` (see below). |
| `scripts/reinstall.sh` | Install the built package into the running container and restart Splunk. |
| `scripts/splunk_search.sh '<spl>'` | Run a search as admin; prints JSON results. |
| `scripts/search_as.sh <user> <password> '<spl>'` | Run a search as any user; prints messages and results. |
| `scripts/splunk_rest.sh <curl args>` | Call the Splunk REST API as admin. |

All of them target `viewdns-splunk` unless `SPLUNK_CONTAINER` is set.

**Stop / reset:**

```bash
docker compose --profile splunk10 down        # stop, keep data
docker compose --profile splunk10 down -v     # stop and delete all Splunk data (API key, cache, indexes)
```

## Repository layout

```
globalConfig.json            UCC: configuration page (settings, proxy, logging) and the alert action
package/                     add-on source (copied into the build)
  app.manifest
  README.md                  user guide (generated from docs/README.template.md; shipped)
  bin/
    viewdns.py               `viewdns` streaming search command
    viewdnsaccount.py        `viewdnsaccount` generating command (account balance, free)
    ta_viewdns_lookup_handler.py   REST endpoint /services/ta_viewdns/lookup (capability viewdns_lookup)
    ta_viewdns_settings_handler.py validates the API key when the configuration is saved
    ta_viewdns/
      client.py              ViewDNS HTTP client: retries, typed errors, key scrubbing
      actions.py             the 22 lookups: validation, API call, parsing
      enrich.py              engine: dedupe, KV cache, credit guard, fatal errors, circuit breaker
      remote.py              caller side of the REST endpoint (used by commands and the alert)
      output.py              shapes results into events (mv / rows)
      splunk_env.py          settings/secrets, KV store cache, logging
      modalert_viewdns_enrichment_helper.py   the ViewDNS Enrichment alert action
  default/                   commands, searchbnf, props, transforms, collections, authorize, savedsearches,
                             dashboard (data/ui/views/viewdns_investigate.xml), nav
  metadata/default.meta
  static/, appserver/static/ icons
build/append/                stanzas appended to UCC-generated conf files (UCC overwrites, doesn't merge)
scripts/                     build and Docker helpers
tests/unit/                  pytest unit tests (mocked HTTP; fixtures in tests/fixtures/)
tests/smoke/smoke_test.py    live API smoke test (not shipped)
tools/                       dev tools: icon generator, README/reference generator
docs/                        README template (source of package/README.md)
docker-compose.yml           local Splunk 9.4 (+ optional 10.6)
```

## Build and package

```bash
scripts/build.sh            # version from globalConfig.json
scripts/build.sh 1.0.1      # explicit version
```

The script:

1. Stages the build in a temporary directory on a native filesystem, so file modes are right even when the repo is
   on a Windows drive under WSL.
2. Runs `ucc-gen build`, installing `package/lib/requirements.txt` with `--no-binary=charset-normalizer` so the
   package contains no compiled `.so` files.
3. Patches the UCC-generated settings REST handler to use `ViewDNSSettingsHandler`, the key check on save. UCC has no
   hook for this on settings tabs, and the script fails loudly if UCC's output changes shape.
4. Appends `build/append/*.conf` to the generated conf files.
5. Strips `__pycache__`, fails on any compiled binary, sets modes (dirs 755, files 644, `bin/*.py` 755) and runs
   `ucc-gen package` into `dist/`.

`output/TA-viewdns/` keeps an unpacked copy for inspection.

`app.conf` has `check_for_updates = true` (from `meta.checkForUpdates` in `globalConfig.json`), as Splunkbase
requires. For a private build installed directly into a Splunk Cloud stack instead of from Splunkbase, set it to
`false`.

Pinned dependencies (`package/lib/requirements.txt`):

- solnlib is pinned to 7.0.0 because 8.x pulls in grpcio (a compiled binary) and OpenTelemetry.
- `urllib3<2` is required by splunktaucclib.

After changing lookups, regenerate the user guide's reference table:

```bash
.venv/bin/python tools/gen_readme.py
```

## Tests

**Unit tests:** mocked HTTP; fixtures are the XSOAR pack's test data plus live captures (`live_*.json`) and the API
documentation samples (`docs_*.json`).

```bash
.venv/bin/python -m pytest                          # 179 tests
.venv/bin/python -m pytest --cov=package/bin        # with coverage
```

**Live smoke test** (real API, hard budget of 30 HTTP calls, never shipped):

```bash
VIEWDNS_API_KEY=<key> .venv/bin/python tests/smoke/smoke_test.py                                # 20 calls, 16 queries
VIEWDNS_API_KEY=<key> .venv/bin/python tests/smoke/smoke_test.py --include-paid --include-live  # 28 calls
```

Instead of passing `VIEWDNS_API_KEY` on the command line, you can put it in `.env`. `--include-live` runs port scan,
ping and traceroute against viewdns.info.

**AppInspect:**

```bash
.venv/bin/splunk-appinspect inspect dist/TA-viewdns-1.0.0.tar.gz --mode precert --included-tags cloud
.venv/bin/splunk-appinspect inspect dist/TA-viewdns-1.0.0.tar.gz --mode precert      # full Splunkbase set
```

Both report 0 failures and 0 errors. The remaining warnings are informational or come from UCC-generated UI files
(SplunkJS telemetry, the configuration page's Mako template) and bundled libraries (splunk-sdk version notice,
solnlib internals, PySocks metadata).

## Secrets

- The API key is only ever stored in Splunk's credential store. In this repo it lives only in your git-ignored
  `.env`.
- `.gitignore` excludes `.env`, `local/` directories, `passwords.conf`, build output and the virtualenv.
- Never commit a `local/` directory exported from a Splunk instance: it contains the encrypted key.

## Support

support@viewdns.info · issues: <https://github.com/viewdns/splunk-addon/issues>

## License

Apache License 2.0. See `package/LICENSES/Apache-2.0.txt`.
