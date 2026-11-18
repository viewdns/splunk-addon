#!/usr/bin/env bash
# Runs a search on the local docker Splunk and prints results + messages as JSON lines.
# Usage: scripts/splunk_search.sh '<spl>'   (the leading "search"/"|" is up to you)
set -euo pipefail
cd "$(dirname "$0")/.."
exec scripts/splunk_rest.sh https://localhost:8089/servicesNS/admin/search/search/jobs/export \
    --data-urlencode "search=$1" -d output_mode=json -d exec_mode=oneshot
