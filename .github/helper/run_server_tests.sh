#!/usr/bin/env bash
# Check the runner's result and committed fixture cleanup.

set -euo pipefail

if [[ $# -lt 1 || -z "$1" ]]; then
	echo "usage: $0 <site> [run-tests options]" >&2
	exit 2
fi

site=$1
shift
output_dir=$(mktemp -d)
output_file="$output_dir/suite"
trap 'rm -rf "$output_dir"' EXIT

if bench --site "$site" execute passkeys.tests.committed_state.snapshot > "$output_dir/before"; then
	:
else
	snapshot_status=$?
	echo "server tests: could not snapshot committed state before the suite" >&2
	exit "$snapshot_status"
fi

if bench --site "$site" run-tests --app passkeys "$@" 2>&1 | tee "$output_file"; then
	bench_status=0
else
	bench_status=$?
fi

if (( bench_status != 0 )); then
	echo "server tests: bench exited with status $bench_status" >&2
elif python - "$output_file" <<'PY'
import re
import sys
from pathlib import Path

ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RUN_SUMMARY = re.compile(r"^Ran ([0-9]+) tests? in [^\r\n]+$", re.MULTILINE)
FINAL_SUMMARY = re.compile(r"\s*(OK|FAILED)(?: \([^\r\n]*\))?\s*(?:\r?\n|$)")

output = ANSI_ESCAPE.sub("", Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
runs = list(RUN_SUMMARY.finditer(output))
if not runs:
	raise SystemExit("server tests: missing or unrecognized unittest run summary")

last_run = runs[-1]
if int(last_run.group(1)) == 0:
	raise SystemExit("server tests: unittest ran zero tests")
summary = FINAL_SUMMARY.match(output, last_run.end())
if not summary:
	raise SystemExit("server tests: missing successful final unittest summary")
if summary.group(1) == "FAILED":
	raise SystemExit("server tests: unittest reported a FAILED final summary")
PY
then
	bench_status=0
else
	bench_status=$?
fi

guard_status=0
if ! bench --site "$site" execute passkeys.tests.committed_state.snapshot > "$output_dir/after"; then
	echo "server tests: could not snapshot committed state after the suite" >&2
	guard_status=1
elif diff -u --label 'committed state before' --label 'committed state after' \
	"$output_dir/before" "$output_dir/after"; then
	echo "server tests: no committed-state leaks"
else
	echo "server tests: committed-state leak (removed/changed baseline rows marked -, added/changed rows marked +)" >&2
	guard_status=1
fi

if (( bench_status != 0 )); then
	exit "$bench_status"
fi
exit "$guard_status"
