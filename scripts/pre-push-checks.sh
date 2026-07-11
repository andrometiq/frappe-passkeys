#!/bin/bash
# Local pre-push gate for frappe-passkeys (design/ci-plan.md §10 item 1 —
# the cheap, always-run half; the full 3x2 matrix stays CI's job).
#
# Checks:
#   1. Lint — pre-commit if configured, else ruff (reads pyproject.toml).
#   2. python3.10 -m compileall on the shipped package (passkeys/) — the v15
#      syntax floor: py3.11+/3.14-only syntax must fail HERE, not in the v15
#      CI cell. Falls back to `uv run --python 3.10` when python3.10 is absent.
#   3. (opt-in) one real matrix cell: server tests on your dev bench —
#      export PASSKEYS_DEV_BENCH=/path/to/frappe-bench and
#      PASSKEYS_DEV_SITE=<site> to enable.
#
# Tools (pre-commit, uv for the 3.10 interpreter) are taken from PATH when
# present, else auto-installed into a cached venv under
# ${XDG_CACHE_HOME:-$HOME/.cache}/frappe-passkeys/tools-venv — no global
# installs, works from any (or no) active virtualenv.
#
# Pieces whose inputs don't exist yet (scaffold phase) skip with a notice;
# a check that RUNS and fails blocks the push.
#
# Wire-up (optional):  printf '#!/bin/sh\nexec bash scripts/pre-push-checks.sh\n' \
#                        > .git/hooks/pre-push && chmod +x .git/hooks/pre-push

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 1

failures=0
note() { printf '\033[1;34m[pre-push]\033[0m %s\n' "$*" >&2; }
skip() { printf '\033[1;33m[pre-push SKIP]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[pre-push OK]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pre-push FAIL]\033[0m %s\n' "$*"; failures=$((failures + 1)); }

# Cached tools venv: PATH-missing tools (pre-commit, uv) are pip-installed
# here once and reused. Prints the tool's binary path; fails silently to "".
tools_venv="${XDG_CACHE_HOME:-$HOME/.cache}/frappe-passkeys/tools-venv"
ensure_tool() { # $1 = binary name == pip package name
  local bin="$tools_venv/bin/$1"
  if [ ! -x "$bin" ]; then
    note "installing $1 into $tools_venv (one-time; reused afterwards)"
    { python3 -m venv "$tools_venv" \
        && "$tools_venv/bin/python" -m pip install --quiet --upgrade pip \
        && "$tools_venv/bin/python" -m pip install --quiet "$1"; } >&2 || return 1
  fi
  [ -x "$bin" ] && printf '%s\n' "$bin"
}

# ---------------------------------------------------------------- 1. lint
lint_ran=0
if [ -f .pre-commit-config.yaml ]; then
  pc_bin="$(command -v pre-commit || true)"
  if [ -z "$pc_bin" ]; then
    pc_bin="$(ensure_tool pre-commit || true)"
  fi
  if [ -n "$pc_bin" ]; then
    if "$pc_bin" run --all-files; then
      ok "pre-commit"
    else
      fail "pre-commit found issues"
    fi
    lint_ran=1
  fi
fi
if [ "$lint_ran" = 0 ] && [ -f pyproject.toml ]; then
  ruff_bin="$(command -v ruff || true)"
  if [ -z "$ruff_bin" ]; then
    ruff_bin="$(ensure_tool ruff || true)"
  fi
  if [ -n "$ruff_bin" ]; then
    if "$ruff_bin" check .; then
      ok "ruff check"
    else
      fail "ruff check found issues"
    fi
    lint_ran=1
  fi
fi
if [ "$lint_ran" = 0 ]; then
  skip "lint: no linter config yet, or pre-commit/ruff unavailable and not installable"
fi

# ------------------------------- 2. v15 syntax floor: compileall on py3.10
if [ -d passkeys ]; then
  # keep .pyc out of the working tree
  export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/frappe-passkeys-pyc"
  compile_cmd=()
  compile_label=""
  if command -v python3.10 >/dev/null 2>&1; then
    compile_cmd=(python3.10)
    compile_label="python3.10"
  else
    uv_bin="$(command -v uv || true)"
    if [ -z "$uv_bin" ]; then
      uv_bin="$(ensure_tool uv || true)"
      if [ -n "$uv_bin" ]; then
        # keep repo-provisioned uv's interpreters contained in our cache dir
        export UV_PYTHON_INSTALL_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/frappe-passkeys/uv-pythons"
      fi
    fi
    if [ -n "$uv_bin" ]; then
      compile_cmd=("$uv_bin" run --python 3.10 --no-project -- python)
      compile_label="uv-managed python 3.10"
    fi
  fi
  if [ "${#compile_cmd[@]}" -gt 0 ]; then
    if "${compile_cmd[@]}" -m compileall -q -f passkeys; then
      ok "compileall on $compile_label (v15 syntax floor)"
    else
      fail "passkeys/ does not compile on python 3.10 — would break the v15 CI cell"
    fi
  else
    fail "no python3.10, no uv, and auto-install failed — cannot enforce the v15 syntax floor (install one: 'uv python install 3.10' or 'pyenv install 3.10')"
  fi
else
  skip "compileall: passkeys/ package not scaffolded yet"
fi

# The WebAuthn golden-vector pack (passkeys/tests/vectors/) is validated by the
# frappe test suite (passkeys.tests.test_engine_vectors), run by CI and by the
# opt-in dev-bench cell below.

# --------------------------- 3. opt-in: server tests on the dev bench
if [ -n "${PASSKEYS_DEV_BENCH:-}" ] && [ -n "${PASSKEYS_DEV_SITE:-}" ]; then
  if (cd "$PASSKEYS_DEV_BENCH" && bench --site "$PASSKEYS_DEV_SITE" run-tests --app passkeys); then
    ok "server tests on dev bench ($PASSKEYS_DEV_SITE)"
  else
    fail "server tests failed on dev bench ($PASSKEYS_DEV_SITE)"
  fi
else
  skip "dev-bench server tests: set PASSKEYS_DEV_BENCH + PASSKEYS_DEV_SITE to run one real matrix cell locally"
fi

# ------------------------------------------------------------------ result
echo
if [ "$failures" -gt 0 ]; then
  fail "$failures check(s) failed — push blocked"
  exit 1
fi
ok "all pre-push checks green"
