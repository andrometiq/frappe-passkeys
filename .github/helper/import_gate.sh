#!/bin/bash
# Import-graph gate.
#
# The hook-path modules — passkeys.auth_hooks, passkeys.boot, passkeys.install,
# passkeys.shims.login_page — fire on every login of every user and on every
# website render / Desk load. They MUST import without the `webauthn` library
# installed (directly or transitively): a broken cryptography wheel must never
# take down logins. webauthn may only be imported lazily inside ceremony
# endpoint bodies.
#
# Environment:
#   FRAPPE_GATE_REF     frappe ref installed so `import frappe` works
#                       (default version-15 — matches the lint job's Python 3.10)
#   IMPORT_GATE_STRICT  "1" → a missing hook-path module FAILS the gate;
#                       "0" (default) → missing modules only warn (scaffold phase)
#
# frappe itself depends on webauthn on NO branch, and the app is
# installed with --no-deps, so the venv provably lacks webauthn.

set -euo pipefail

ref="${FRAPPE_GATE_REF:-version-15}"
strict="${IMPORT_GATE_STRICT:-0}"

if [ ! -f pyproject.toml ] || [ ! -d passkeys ]; then
  msg="import gate: app package not scaffolded yet (pyproject.toml / passkeys/ missing)"
  if [ "$strict" = "1" ]; then
    echo "::error::$msg"
    exit 1
  fi
  echo "::warning::$msg — skipping (IMPORT_GATE_STRICT=0)"
  exit 0
fi

workdir="$(mktemp -d)"
venv_dir="$workdir/gate-venv"
python -m venv "$venv_dir"
# shellcheck disable=SC1091
source "$venv_dir/bin/activate"
python -m pip install --quiet --upgrade pip

echo "::group::install frappe ($ref) + app (--no-deps) into the gate venv"
git clone --quiet --depth 1 --branch "$ref" https://github.com/frappe/frappe "$workdir/frappe"
python -m pip install --quiet "$workdir/frappe"
python -m pip install --quiet --no-deps -e .
echo "::endgroup::"

IMPORT_GATE_STRICT="$strict" python - <<'PY'
import importlib
import importlib.util
import os
import sys

if importlib.util.find_spec("webauthn") is not None:
    print("::error::webauthn is installed in the gate venv - the gate would prove nothing")
    sys.exit(1)

strict = os.environ.get("IMPORT_GATE_STRICT", "0") == "1"
modules = [
    "passkeys.auth_hooks",
    "passkeys.boot",
    "passkeys.install",
    "passkeys.shims.login_page",
]
failed = []
missing = []
for name in modules:
    try:
        spec = importlib.util.find_spec(name)
    except ModuleNotFoundError:
        spec = None
    if spec is None:
        missing.append(name)
        continue
    try:
        importlib.import_module(name)
    except Exception as exc:  # any import failure is a gate failure
        failed.append((name, repr(exc)))

if "webauthn" in sys.modules:
    print("::error::a hook-path module imported webauthn transitively - hook-path import discipline violation")
    sys.exit(1)

for name, err in failed:
    print(f"::error::import gate: {name} failed to import without webauthn: {err}")
for name in missing:
    if strict:
        print(f"::error::import gate: {name} not present (IMPORT_GATE_STRICT=1)")
    else:
        print(f"::warning::import gate: {name} not present (scaffold phase - tolerated)")

if failed or (strict and missing):
    sys.exit(1)

checked = [m for m in modules if m not in missing]
print("import gate OK:", ", ".join(checked) if checked else "(no hook-path modules yet)")
PY
