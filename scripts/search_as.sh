#!/usr/bin/env bash
# Runs a search on the local docker Splunk as a given user; prints the job's messages and results.
# Set SPLUNK_CONTAINER=viewdns-splunk10 to target the Splunk 10 instance.
# Usage: scripts/search_as.sh <user> <password> '<spl>'
set -euo pipefail
U="$1"; P="$2"; Q="$3"
c() { docker exec "${SPLUNK_CONTAINER:-viewdns-splunk}" curl -sk -u "$U:$P" "$@"; }
SID=$(c "https://localhost:8089/servicesNS/$U/search/search/jobs" --data-urlencode "search=$Q" \
      -d exec_mode=blocking -d output_mode=json | python3 -c 'import json,sys;print(json.load(sys.stdin)["sid"])')
c "https://localhost:8089/servicesNS/$U/search/search/jobs/$SID?output_mode=json" \
  | python3 -c 'import json,sys;print("messages:",json.load(sys.stdin)["entry"][0]["content"].get("messages"))'
c "https://localhost:8089/servicesNS/$U/search/search/jobs/$SID/results?output_mode=json&count=0" \
  | python3 -c 'import json,sys;[print(" ",json.dumps(r)) for r in json.load(sys.stdin)["results"]]'
