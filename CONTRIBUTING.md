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
- **Security vulnerabilities must not go in public issues** — follow the disclosure process in
  [`docs/security.md`](docs/security.md).
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

Run the suites before you push — CI runs all three against Frappe v15, v16, and develop:

```bash
bench --site <site> run-tests --app passkeys      # Python server suite
node --test 'passkeys/tests/js/*.test.js'          # dependency-free client-logic suite
# Cypress end-to-end: see .github/workflows/ci.yml for the exact invocation
```

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
- Link the issue you close with `Closes #123`.

## Code style

`pre-commit` is the style gate: **Ruff** (import sort, lint, format) for Python plus the standard
whitespace / JSON / TOML / YAML hooks. Run `pre-commit run --all-files` before pushing — CI checks
formatting and does not fix it for you.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
