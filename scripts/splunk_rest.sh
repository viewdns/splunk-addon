#!/usr/bin/env bash
# Runs a REST call against the local docker Splunk as admin. Usage: scripts/splunk_rest.sh <curl args...>
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .env
docker exec "${SPLUNK_CONTAINER:-viewdns-splunk}" curl -sk -u "admin:${SPLUNK_PASSWORD}" "$@"
