# Agent Guide

This repo is a Frappe **app** that adds WebAuthn / passkey authentication to a Frappe site:
passwordless login, passkey-as-second-factor, and an `@passkey_protected` action-confirmation
primitive other apps can build on. It is built to be **mergeable into Frappe core** — one
feature-detecting codebase across `version-15`, `version-16`, and `develop`, no monkeypatching,
all enforcement server-side. Prefer small, direct changes that keep the endpoints, hooks, and
client bundles thin and put real behavior in the domain modules.

Read `CONTRIBUTING.md` before starting — it owns the human process (dev setup, branch model,
commit style, the exact test commands, releases). This guide owns the code map and the taste;
it does not repeat what `CONTRIBUTING.md` says.

## Main Rules

- Put real behavior in the domain modules (`engine`, `policy`, `state`, `posture`, `confirm`,
  `session`, `install`) and the DocType controllers. Keep the whitelisted endpoints (`passkey.py`,
  `api/`), the Frappe hooks (`hooks.py`), and the client bundles (`public/js/*.bundle.js`) thin:
  parse, authorize, then delegate.
- **Hook-path import discipline is mandatory.** Any module reachable from an every-request hook
  chain — `on_login`, `on_session_creation`, `on_logout`, `after_request`, `extend_bootinfo`,
  `update_website_context`, `doc_events`, install/migrate — must NOT import `webauthn` (directly or
  transitively). `webauthn` is imported lazily, inside ceremony endpoint bodies only, so a broken
  crypto wheel can never take down login or boot. The only top-level `import webauthn` lives in
  `engine.py`. `import_gate.sh` enforces this in CI — keep it green.
- All enforcement is **server-side**. The client may gate UI on site policy, but the real boundary
  is a whitelisted server check (`frappe.only_for(...)`, ownership ladders, veto hooks). Never
  trust a client-supplied identity or capability flag.
- **Fail closed.** A consumed, expired, evicted, or unverifiable ceremony/grant returns a uniform
  typed error, never a silent pass. Do not add a skip-verification path.
- Every behavior change ships with a test in the same change, and the relevant `docs/*.md` (and
  `CHANGELOG.md` for auth / migration / origin / lifecycle changes) is updated with it.
- Do not commit generated assets (`passkeys/public/dist/` is gitignored; CI rebuilds it) or
  scratch/plan markdown.

## Useful Entry Points

- `passkeys/hooks.py`: the Frappe app manifest — every seam into core (asset bundles, `doctype_js`,
  install/uninstall/migrate, website-context shims, boot, session lifecycle, `after_request`,
  `doc_events`). Start here to see how the app attaches to Frappe.
- `passkeys/passkey.py`: guest-facing first-factor passwordless login (`begin_login` /
  `verify_login`), the password+passkey second-factor flow (`login_with_password` /
  `verify_second_factor` / `fallback_to_otp`), the uv-setup step-up, the guest translations
  endpoint, and the User cascade. Carries the typed-error wire contract.
- `passkeys/api/registration.py`: authenticated, sudo-gated registration ceremony endpoints.
- `passkeys/api/credentials.py`: a user's own credential management (list / rename / delete) and the
  per-user `passkey_only_login` switch. Identity comes only from `frappe.session.user`.
- `passkeys/confirm.py`: the **public API** for other apps — `@passkey_protected` and the
  confirmation ceremony / grant endpoints. Treat its decorator signature as a contract.
- `passkeys/engine.py`: the crypto core — `py_webauthn` options/verify wrappers plus app-side
  policy. The only place a top-level `import webauthn` is allowed.
- `passkeys/policy.py`: RP ID / origin resolution, from pinned config at enable time — never from a
  guest path, never from `Host` / `X-Forwarded-*` headers.
- `passkeys/state.py`: the single-use `passkeys:*` ceremony / sudo / grant / uv-setup store. Raw
  `redis.Redis` ops, JSON values, single owner, atomic single-use consume.
- `passkeys/session.py`, `passkeys/auth_hooks.py`, `passkeys/boot.py`, `passkeys/cookie_determinism.py`:
  the hook-path modules (sudo-window seed/clear, `passkey_only_login` veto + System Settings guard,
  boot flag + nudge state, `after_request` sid-reseed strip). All `webauthn`-free by rule.
- `passkeys/posture.py`, `passkeys/enforcement_admin.py`: the admin security-posture verdict (pure
  `classify_posture` + config-reading builder) and the System-Manager-only stuck-user recovery
  endpoints (per-user exemption, grace reset).
- `passkeys/well_known.py`: guest-readable mobile-association files (Android `assetlinks.json`, iOS
  `apple-app-site-association`).
- `passkeys/passkeys/doctype/`: persisted domain objects — `passkey_settings` (the single config
  doctype; its controller also exposes two whitelisted reads, `get_resolved_rp_id` /
  `get_security_posture`), `webauthn_credential`, `webauthn_user_handle`, `passkey_enforcement_role`.
- `passkeys/shims/`: `login_page.py` and `portal_nudge.py` — conditional asset delivery that folds
  away on the core merge.
- Tests: `passkeys/tests/` (Python server suite + `fake_webauthn.py` browserless mode),
  `passkeys/tests/js/*.test.js` (dependency-free `node --test` client logic), and
  `cypress/integration/*.cy.js` (browser end-to-end).
- Docs: `docs/` (operator-facing) and `docs/upstream/` (the core-adoption proposal + patch mapping —
  update it when you change a seam core would inherit).

## Design Expectations

The app is layered, not an object graph. Respect the layers:

1. **Wire** — `passkey.py`, `api/*`, `confirm.py`, `well_known.py`, `enforcement_admin.py`.
   Whitelisted, method-scoped (`POST` for actions; `GET` only for the guest-readable association
   files and the translations catalog; `allow_guest` only where a guest ceremony needs it), typed
   errors out. Parse, authorize,
   rate-limit, delegate — no crypto orchestration inline.
2. **Domain** — `engine` (verify), `policy` (RP/origin), `state` (single-use store), `posture`
   (verdict), `confirm` / `session` (grants + sudo window), `install` (guards). New behavior lives
   here.
3. **Persistence** — the four DocTypes. `Passkey Settings` is the single owner of the enable flags
   and RP/origin config; do not scatter that state.
4. **Attachment** — `hooks.py` + `shims/` + `public/js/*.bundle.js`. Thin glue.

Before writing a feature, ask which layer owns it. A whitelisted endpoint that starts doing
verification math, header parsing, or Redis bookkeeping inline is a smell — push it into the
engine / policy / state module.

Load-bearing invariants (do not weaken without a security review): one owner for state; single-use,
atomic, fail-closed ceremony/grant consumption; RP ID / origins from pinned config at enable time,
never from headers; hook-path modules import no `webauthn`.

## Code Taste

Frappe house style: **tabs**, double quotes, `ruff` config in `pyproject.toml` — do not reformat to
spaces. These rules apply to any change here:

- Clean over clever. Prefer explicit config over implicit behavior.
- Keep functions small (~25 lines is a target, not a reason to split readable code) and cyclomatic
  complexity low. Keep files in a workable band (roughly 100–500 lines); when a folder grows, group
  related files into a subfolder instead of adding more same-prefix modules. The wire modules that
  fold into `frappe/passkey.py` on the core merge (`passkey.py`, `confirm.py`, `install.py`) run
  long by design — don't split them to satisfy the band, and don't let them grow further either. The
  frozen client bundles (`passkey_common.bundle.js`, `passkey_login.bundle.js`,
  `passkey_desk.bundle.js`, `passkey_manage_common.bundle.js`) are cohesive, load-order-bearing
  components that run long by design; don't split them, and don't let them grow further.
- Avoid abbreviations. Use the standard library and existing repo helpers before new logic. Reuse
  existing patterns; write as little new code as the change needs; delete or simplify before adding.
- Keep comments and docstrings terse — explain only what the code doesn't already say. No banner
  comment at the top of a file; use a short module/class/method docstring. Put "why this changed" in
  the commit message, not inline.
- Keep one owner for state that can drift out of sync. Keep temporary state scoped — don't let it
  leak across module boundaries.
- Fail loudly, near the bug. Don't hide corrupt or partial state behind a broad `try/except` or
  fallback. Retry only operations that are safe to repeat.
- Name boolean-returning helpers with `is_` / `has_`. Prefer a `@property` for a no-argument
  noun-like value; use `get_<noun>()` for argument-taking or multi-step work.
- Default to public functions/methods. Use a leading underscore only for raw parsing,
  security-sensitive validation, or genuinely internal plumbing — not because a helper currently has
  one caller. Don't split into more helpers than the change needs; a single-use one-liner often
  reads better inline.
- Always add or update tests for behavior changes, and make them pass. Logic and validation stay
  server-side; a test that only proves the client gate is not enough.
- Build the minimum working change, then iterate.

## Working Rules

- Read `CONTRIBUTING.md` for setup, commit style, and the browserless WebAuthn test mode. The
  branch model is its: `develop` is the PR target; `version-15` / `version-16` are the released
  lines. A change reaches a released line as a clean cherry-pick verified per branch — say
  `needs backport` in the PR if you can't do it yourself. The three branches share one
  feature-detecting codebase and differ only in the pinned `__version__` — never write
  version-forked logic.
- Before a bug fix, find the root cause first — don't loosen a test to match new behavior.
- Run the gates before pushing (exact invocations in `CONTRIBUTING.md` and `.github/workflows/ci.yml`):
  `pre-commit run --all-files` (ruff import-sort / lint / format — CI checks, does not fix);
  `bench --site <site> run-tests --app passkeys` (Python server suite);
  `node --test passkeys/tests/js/*.test.js` (client-logic suite); and the Cypress run — keep
  `cypress.config.js` at `retries: 0` and `testIsolation: true`.
- This repo is **public and upstream-bound**. Keep every committed file generic and free of secrets
  and personal data; CI runs a `gitleaks` secret scan over full history. Never weaken a security
  gate to make a test pass.
- When you change a seam core would inherit, update `docs/upstream/` in the same change.

## Docs

Keep docs concise and current in the same change as the behavior. Operators should find the workflow
and the security consequence quickly (`docs/`); an agent should find the layer boundaries and safe
edit locations from this guide and the module docstrings without reading long prose. Security model:
`docs/security.md`. The core-merge contract: `docs/upstream/`.
