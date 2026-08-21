#!/bin/bash
# Import-graph gate.
#
# Every callable referenced by hooks.py, plus every module participating in the
# native-dormancy guard, MUST import without the `webauthn` library installed.
# A broken cryptography wheel must never take down a login, page render, install,
# migration, or dormant-shell handoff. webauthn may only be imported lazily
# inside ceremony endpoint bodies.
#
# Environment:
#   FRAPPE_GATE_REF     frappe ref installed so `import frappe` works
#                       (default version-15 — matches the lint job's Python 3.10)
# Frappe itself does not provide webauthn on the pinned gate ref, and the app is
# installed with --no-deps, so the venv provably lacks webauthn. This is an
# import-availability gate, not proof of native-core runtime dormancy; that claim
# requires a concrete upstream capability contract and dedicated integration run.

set -euo pipefail

ref="${FRAPPE_GATE_REF:-version-15}"

test -s pyproject.toml
test -s passkeys/hooks.py

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
venv_dir="$workdir/gate-venv"
python -m venv "$venv_dir"
# shellcheck disable=SC1091
source "$venv_dir/bin/activate"

echo "::group::install frappe ($ref) + app (--no-deps) into the gate venv"
git init --quiet "$workdir/frappe"
git -C "$workdir/frappe" remote add origin https://github.com/frappe/frappe.git
git -C "$workdir/frappe" fetch --quiet --depth 1 origin "$ref"
git -C "$workdir/frappe" checkout --quiet --detach FETCH_HEAD
echo "Resolved frappe import-gate ref to $(git -C "$workdir/frappe" rev-parse HEAD)"
python -m pip install --quiet "$workdir/frappe"
python -m pip install --quiet --no-deps -e .
echo "::endgroup::"

python - <<'PY'
import ast
import importlib
import importlib.util
import runpy
import sys
from pathlib import Path

if importlib.util.find_spec("webauthn") is not None:
    print("::error::webauthn is installed in the gate venv - the gate would prove nothing")
    sys.exit(1)

HOOK_KEYS = {
    "after_install",
    "after_migrate",
    "after_request",
    "before_install",
    "before_uninstall",
    "doc_events",
    "extend_bootinfo",
    "on_login",
    "on_logout",
    "on_session_creation",
    "update_website_context",
}
DORMANCY_MARKERS = {
    "_refuse_if_core_native",
    "dormant",
    "is_core_native",
    "refuse_if_core_native",
}


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from strings(child)


hook_table = runpy.run_path("passkeys/hooks.py")
hook_targets = sorted(
    {target for key in HOOK_KEYS for target in strings(hook_table.get(key))}
)
if not hook_targets:
    print("::error::import gate found no hook targets in passkeys/hooks.py")
    sys.exit(1)

patches_path = Path("passkeys/patches.txt")
if not patches_path.is_file():
    print("::error::import gate: passkeys/patches.txt is missing")
    sys.exit(1)
patch_modules = []
for raw_line in patches_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith(("[", "#", "execute:")):
        continue
    patch_modules.append(line)
if not patch_modules:
    print("::error::import gate found no patch modules in passkeys/patches.txt")
    sys.exit(1)

modules = {"passkeys.hooks", *patch_modules}
target_attributes = []
for target in hook_targets:
    module_name, separator, attribute = target.rpartition(".")
    if not separator:
        print(f"::error::invalid hook target: {target}")
        sys.exit(1)
    modules.add(module_name)
    target_attributes.append((target, module_name, attribute))

for path in Path("passkeys").rglob("*.py"):
    if "tests" in path.parts:
        continue
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    if DORMANCY_MARKERS & (names | attributes):
        modules.add(".".join(path.with_suffix("").parts))

failed = []
imported = {}
for name in sorted(modules):
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError):
        spec = None
    if spec is None:
        failed.append((name, "module not found"))
        continue
    try:
        imported[name] = importlib.import_module(name)
    except Exception as exc:  # any import failure is a gate failure
        failed.append((name, repr(exc)))

for target, module_name, attribute in target_attributes:
    module = imported.get(module_name)
    if module is not None and not callable(getattr(module, attribute, None)):
        failed.append((target, "hook target is missing or not callable"))

if "webauthn" in sys.modules:
    print("::error::a hook-path module imported webauthn transitively - hook-path import discipline violation")
    sys.exit(1)

for name, err in failed:
    print(f"::error::import gate: {name} failed to import without webauthn: {err}")

if failed:
    sys.exit(1)

print(
    f"import gate OK: {len(hook_targets)} hook targets; "
    f"{len(patch_modules)} patch modules; {len(modules)} gated modules"
)
PY
