#!/usr/bin/env bash
# Release gate: fail when upstream's provider-name list has a change this repo's snapshot has
# lacked for more than MAX_DAYS days (docs/aaguid-map.md). Needs `gh` with a token.
set -euo pipefail
MAX_DAYS=${MAX_DAYS:-30}
SNAPSHOT=${SNAPSHOT:-passkeys/public/aaguid-map.json}
UPSTREAM=passkeydeveloper/passkey-authenticator-aaguids

snapshot_date=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["_meta"]["upstream_date"])' "$SNAPSHOT")
oldest_missing=$(gh api "repos/$UPSTREAM/commits?path=combined_aaguid.json&since=${snapshot_date}T23:59:59Z&per_page=100" \
	--jq '[.[].commit.committer.date] | min // empty')

if [ -z "$oldest_missing" ]; then
	echo "Provider names are current (upstream $snapshot_date)."
	exit 0
fi
waiting_days=$(( ( $(date -u +%s) - $(date -u -d "$oldest_missing" +%s) ) / 86400 ))
if [ "$waiting_days" -gt "$MAX_DAYS" ]; then
	echo "::error::Provider names are stale: upstream changed on ${oldest_missing:0:10}, $waiting_days days ago, and $SNAPSHOT is from $snapshot_date. Refresh it (docs/aaguid-map.md) before releasing."
	exit 1
fi
echo "Upstream changed on ${oldest_missing:0:10} ($waiting_days days ago, within $MAX_DAYS); refresh at the next release."
