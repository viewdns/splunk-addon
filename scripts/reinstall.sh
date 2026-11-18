#!/usr/bin/env bash
# Reinstalls the freshly built package into the local docker Splunk and restarts it.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .env
PKG="dist/TA-viewdns-${TA_VERSION:-1.0.0}.tar.gz"
docker exec -u splunk "${SPLUNK_CONTAINER:-viewdns-splunk}" /opt/splunk/bin/splunk install app "/tmp/$PKG" -update 1 -auth "admin:${SPLUNK_PASSWORD}"
docker exec -u splunk "${SPLUNK_CONTAINER:-viewdns-splunk}" /opt/splunk/bin/splunk restart >/dev/null
echo "Reinstalled $PKG"
