# Contributing to Passkeys for Frappe

Thanks for helping. This app is a delivery vehicle for a native Frappe implementation
(see [`docs/upstream/`](docs/upstream/)), so contributions are held to the standard of code that
could land in `frappe/frappe`: one feature-detecting codebase, no monkeypatching, server-side
enforcement, and a test for every behaviour.

## Reporting issues

- Search [existing issues](https://github.com/Andrometiq/frappe-passkeys/issues) first; open one
  issue per bug or request.
- **Bugs** need the Frappe version, exact reproduction steps, what you expected, what happened, and a
  screenshot or short screencast where it helps.
- **Security vulnerabilities must not go in public issues** — follow the private disclosure process
  in [`SECURITY.md`](SECURITY.md).
- General "how do I…" questions belong on the [Frappe forum](https://discuss.frappe.io) or Stack
  Overflow (tag `frappe`), not the issue tracker.

## Development setup

```bash
# Pick the branch you are targeting: develop, version-16, or version-15
bench get-app --branch develop https://github.com/Andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
cd apps/passkeys
pre-commit install
```

Run the suites before you push. Release CI exercises reviewed, pinned Frappe v15, v16, and develop
baselines; the moving-tip workflow fails visibly on drift but does not expand the supported release
range or attest a release candidate:

```bash
bench --site <site> run-tests --app passkeys      # Python server suite
node --test passkeys/tests/js/*.test.js            # dependency-free client-logic suite
# Cypress end-to-end: see .github/workflows/ci.yml for the exact invocation
```

## Browserless WebAuthn test mode

Most of the Python suite exercises the *real* ceremonies without a browser through a bench-guarded
fake-service layer, `passkeys/tests/fake_webauthn.py`: real server-minted challenges, the unmodified
`py_webauthn` verifier, and every app-side check, driven by a deterministic software authenticator
(`SoftAuthenticator`). It is reusable — adopt it in your own app's CI to test passkey flows headlessly.

```python
from passkeys.tests import fake_webauthn

# register → login (discoverable) → delete, all through the real verify paths:
report = fake_webauthn.round_trip()
assert report["session_matches"] and report["credential_gone"]

# or enrol a committed passkey for a specific user to seed a fixture:
fake_webauthn.enable()                       # point settings at a test RP + origin
fake_webauthn.enroll(user="alice@example.com")
```

Every whitelisted entry point calls `_guard()` first (`frappe.only_for("System Manager")` plus a
`developer_mode` / `flags.in_test` check), so it is reachable only by a System Manager on a dev/test
bench — never in production, never by a guest — and folds away with `shims/` on the core merge. Two
invariants keep it safe:

- **It adds no skip-verification path.** Nothing touches `engine.py`; the authenticator emits
  spec-valid payloads that pass the *unmodified* verifier, so a tampered assertion is still rejected.
- **It relaxes only the enable-time HTTPS validator** (an `http://*.localhost` origin is accepted for
  a local bench); the ceremony-time `expected_origin` check the verifier enforces is fully intact.

## Branches

The code is a single feature-detecting codebase; the branches mirror `frappe/frappe` so users
install the line that matches their Frappe version, and they differ only in the pinned `__version__`.

| Branch | For |
| --- | --- |
| `develop` | New features, and the default target for pull requests. |
| `version-16` | Fixes that must ship to the Frappe v16 line. |
| `version-15` | Fixes that must ship to the Frappe v15 line. |

Open features against `develop`. If a fix needs to reach a released line, target the matching
`version-*` branch (or say so in the PR so it can be backported). Don't commit directly to `develop`.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/), matching `frappe/frappe`:

```
type(optional-scope): short imperative summary

Optional body explaining what changed and why — the diff already shows how.
Wrap it at about 72 columns.

Closes #123
```

- **type** is required and lowercase, one of:
  `build`, `chore`, `ci`, `deprecate`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`,
  `test`.
- **scope** is optional and free-form (e.g. `fix(login): …`).
- Keep the summary concise and imperative ("add", not "added").
- `feat` and `fix` drive the version bump and changelog, so classify accurately.
- Reference issues in the footer with `Closes #123`; flag incompatibilities with `BREAKING CHANGE:`.

No `Signed-off-by` / DCO, CLA, or co-author trailer is required — a clear conventional message is all
that's asked.

## Pull requests

- Target the right branch (above) and give the PR a Conventional-Commits-style title.
- All tests pass locally (server, JS unit, and Cypress) and `pre-commit` is clean.
- New behaviour is covered by tests; business logic and validation stay server-side.
- Update the relevant docs under [`docs/`](docs/) when behaviour changes.
- For authentication, migration, origin-policy, or lifecycle changes, update
  [`CHANGELOG.md`](CHANGELOG.md) and verify the [release checklist](docs/release-checklist.md) still
  covers the changed risk.
- Link the issue you close with `Closes #123`.

## Releases

Only maintainers publish releases. A green test run is necessary but not sufficient: the candidate
must satisfy [`docs/release-checklist.md`](docs/release-checklist.md), including a clean worktree,
candidate-specific pinned CI, lifecycle and uninstall-export coverage, staging validation on the
deployment topology, recovery rehearsal, changelog review, and private-data/secret scanning.

Do not describe `develop`, an untagged commit, or an upstream-tip compatibility run as production-ready.
Record exact refs and dates when a document intentionally captures a test snapshot; otherwise avoid
test counts and commit hashes that become stale as soon as the tree changes.

## Code style

`pre-commit` is the style gate: **Ruff** (import sort, lint, format) for Python plus the standard
whitespace / JSON / TOML / YAML hooks. Run `pre-commit run --all-files` before pushing — CI checks
formatting and does not fix it for you.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
