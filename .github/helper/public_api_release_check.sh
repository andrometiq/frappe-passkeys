#!/usr/bin/env bash
# Release gate for RELEASES.md's public-API promise: a name (or endpoint/decorator argument) in
# passkeys/tests/public_api.json at the previous release tag and gone at HEAD must have been listed
# under "deprecated" at that tag, and the new version must raise the middle number.
# Usage: public_api_release_check.sh <previous-release-tag> <new-version> [--allow <name>]...
# --allow exempts one removed name: the security exception in RELEASES.md, said in the changelog.
set -euo pipefail
SNAPSHOT=passkeys/tests/public_api.json
usage="usage: $0 <previous-release-tag> <new-version> [--allow <name>]..."
[ $# -ge 2 ] || { echo "$usage" >&2; exit 2; }
previous_tag=$1 new_version=$2
shift 2
allowed=()
while [ $# -gt 0 ]; do
	[ "$1" = --allow ] && [ $# -ge 2 ] || { echo "$usage" >&2; exit 2; }
	allowed+=("$2")
	shift 2
done
[[ $new_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::$new_version is not a release version (X.Y.Z)" >&2; exit 2; }

git rev-parse --verify --quiet "$previous_tag^{commit}" >/dev/null || { echo "::error::No such tag: $previous_tag" >&2; exit 2; }
if ! git cat-file -e "$previous_tag:$SNAPSHOT" 2>/dev/null; then
	echo "No $SNAPSHOT at $previous_tag: nothing to compare."
	exit 0
fi

previous=$(git show "$previous_tag:$SNAPSHOT")
current=$(git show "HEAD:$SNAPSHOT")
PREVIOUS=$previous CURRENT=$current python3 - "$previous_tag" "$new_version" "${allowed[@]}" <<'EOF'
import json
import os
import re
import sys

tag, version, allowed = sys.argv[1], sys.argv[2], set(sys.argv[3:])
previous, current = json.loads(os.environ["PREVIOUS"]), json.loads(os.environ["CURRENT"])


def get_names(snapshot):
	"""Every public name; an endpoint or decorator argument is ``path(argument)``."""
	names = set()
	for section, entries in snapshot.items():
		if section in ("middle", "deprecated"):
			continue
		names.update(entries)
		if isinstance(entries, dict):
			names.update(f"{path}({argument})" for path, arguments in entries.items() for argument in arguments)
	return names


def get_middle(release):
	match = re.fullmatch(r"v?\d+\.(\d+)\.\d+", release)
	if not match:
		sys.exit(f"::error::{release} is not a release version (X.Y.Z)")
	return int(match[1])


is_middle_raised = get_middle(version) > get_middle(tag)
gone = get_names(previous) - get_names(current)
removed, exempted = sorted(gone - allowed), sorted(gone & allowed)
problems = []
if removed and not is_middle_raised:
	problems.append(f"removed in {version} without raising the middle number of {tag}: {', '.join(removed)}")
not_deprecated = [name for name in removed if name.split("(")[0] not in previous["deprecated"]]
if not_deprecated:
	problems.append(f'removed without first being listed under "deprecated" at {tag}: {", ".join(not_deprecated)}')
for problem in problems:
	print(f"::error::Public API {problem}. RELEASES.md: a release adds the new name and keeps the old one "
		f"working; a later release that raises the middle number removes it. A security fix may pass "
		f"--allow <name>.")
if problems:
	sys.exit(1)
print(f"Public API OK since {tag}: {len(removed)} deprecated and {len(exempted)} --allow name(s) removed.")
EOF
