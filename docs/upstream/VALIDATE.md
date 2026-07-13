# How to validate each patch

The core tests/checks a maintainer would run to confirm each patch is additive and correct.
Run inside a frappe bench with a test site (`bench --site test_site …`). SHAs as in
[`README.md`](./README.md).

**Anchors — re-pin before validating.** `README.md` pins `develop` to
`9b48af62aff88522638e38b1f4738e79ce0902fd`, which is **not fetchable** in the current local clone;
the verifiable develop tip is `512208689eda9fa5c3ce069ce73a88f716e28bb7` (`git -C
apps/frappe rev-parse HEAD`) and every develop anchor lands within ±1–2 lines of it. The v15
(`588e443…`) and v16 (`9a8daf3…`) pins match exactly. **Step 0 of validation:** `git rebase` the
branch onto the current `develop` tip and **re-verify every `file:line` anchor** — develop moves,
so treat the doc's line numbers as approximate until re-confirmed at PR time.

## Patch 01 — `two_factor_methods` registry

**The regression that matters: existing 2FA is byte-identical when no provider is registered.**

```bash
# 1. Existing 2FA suite must stay green with zero provider registered.
bench --site test_site run-tests --module frappe.tests.test_twofactor

# 2. Prove the resolver is inert by default (no two_factor_methods hook on any app):
bench --site test_site execute frappe.twofactor.get_two_factor_method_provider
#    -> None   (=> get_verification_obj/confirm_otp_token take their existing paths)
```

New tests to add in the Stage-1 PR (`frappe/tests/test_twofactor.py`), using a throwaway
in-test provider registered via a monkeypatched `frappe.get_hooks`:

- a registered method's `issue` populates `frappe.local.response["verification"]` + `["tmp_id"]`
  and `confirm_otp_token` routes to its `verify` (both success → session, and failure →
  `login_manager.fail`);
- `authenticate_for_2factor` does **not** re-issue on the verification leg (`tmp_id` present);
- with the method active but **no** provider, OTP App / SMS / Email are unchanged (assert the
  same `verification_obj` shape as `test_twofactor` does today).

Also run the semgrep + translation lints core enforces on `twofactor.py`
(`frappe/semgrep-rules`), and confirm the `login.js` change passes `eslint`/`prettier`.

## Patch 02 — `validate_user_pass_login` allowlist

```bash
bench --site test_site run-tests --module frappe.core.doctype.system_settings.test_system_settings
```

Add/confirm: with `login_with_passkey = 1` and Social/LDAP/email-link all **off**, saving
System Settings with `disable_user_pass_login = 1` **succeeds** (today it `frappe.throw`s); with
all four off it still throws. This is the whole behavioural surface of the one-line change.

## Patch 03 — login-page slot + bundle

- **Server render:** `bench --site test_site execute frappe.www.login.get_context` (with a stub
  context) returns `login_with_passkey` in the context dict; with `login_with_passkey = 0` the
  `.btn-login-with-passkey` button must be absent from the rendered `/login` HTML, and present
  when `1`. A quick check: `curl -s http://test_site:8000/login | grep btn-login-with-passkey`.
- **Envelope compatibility:** the existing `frappe/tests/test_auth.py` login-envelope
  expectations must be untouched (the patch only *adds* a branch/section).
- **Client:** the Cypress login spec (`cypress/integration/login.js` pattern) plus a passkey spec
  driving the CDP **virtual authenticator** — assert the button triggers a ceremony and a
  successful assertion redirects via the returned `home_page`. Run `eslint`/`prettier` on
  `login.js` and `login.html` (prettier formats Jinja-adjacent JS in this repo).
- **Flake mitigation (patches 03/04).** CDP virtual-authenticator specs are flaky in this
  project's own CI (the `confirm.cy.js` grant-semantics suite has intermittently timed out mid-ceremony on
  a `cy.wrap()`). For the maintainer-facing validation story, do **not** rest the additivity
  proof on the browser spec alone: gate the assertion-level checks to **server-side** tests
  (endpoint returns the login envelope; context flag present/absent drives button render) and
  treat the Cypress ceremony as a smoke test with a retry (`retries: 2`) on the ceremony wait.

## Patch 04 — autocomplete token

Pure markup. `curl -s http://test_site:8000/login | grep 'id="login_email"'` shows
`autocomplete="username webauthn"`. No unit test; covered incidentally by the patch-03 Cypress
conditional-UI spec (autofill only surfaces when the token is present). Confirm the HTML still
validates (no lint regression).

## Stage-2 machinery — the plan's riskiest, data-touching parts

The four patches above are the cheap seams. The parts that actually touch user credential data
during an upgrade — the adoption patch, the dormant shell, and the feature-detection interlock —
are **not** exercised by the patch validations above and MUST have their own coverage before the
plan can be called "proven."

### (a) App-installed-site → core-native `bench update` simulation (adoption patch)

Exercises `frappe/patches/vXX/adopt_frappe_passkeys_app.py` end-to-end on a site that already has
the app installed with real data:

1. **Fixture:** a site with the `passkeys` app installed, ≥2 `WebAuthn Credential` rows, a
   `WebAuthn User Handle`, `Passkey Settings` with non-default scalar values, **and** non-empty
   `passkey_enforce_roles` / `passkey_enforce_exempt_roles` (child rows in
   `tabPasskey Enforcement Role`, `parent = "Passkey Settings"`).
2. **Run** the adoption patch (simulate the core `bench update`), then assert:
   - **module flip:** `WebAuthn Credential`, `WebAuthn User Handle`, and `Passkey Enforcement Role`
     DocTypes now report `module = "Core"`; the tables (`tabWebAuthn Credential` etc.) are
     unchanged and every row survived (**zero** row loss on the credential tables).
   - **scalar value-copy:** each `Passkey Settings` scalar landed on the matching System Settings
     field (`login_with_passkey`, `passkey_rp_id`, the enforcement-ladder scalars, the mobile-app
     fields, the notify flags).
   - **child-table re-parent (the row surgery):** the `tabPasskey Enforcement Role` rows now carry
     `parent = "System Settings"` with the correct `parentfield`, and
     `System Settings.passkey_enforce_roles` reads back the same role set — **no orphaned rows**
     left pointing at the dissolved `Passkey Settings` Single.
   - **Property Setter removed** (see (c)); the app is marked dormant.
3. **Idempotency:** re-running the patch is a no-op (patches run once, but assert it does not
   double-copy or duplicate child rows if re-applied).

### (b) Dormant-shell contract (app left installed on a passkey-native core)

The app already ships `passkeys/tests/test_dormancy.py`; the core PR needs the equivalent
assertions against a `find_spec("frappe.passkey") is not None` (core-native) state:

- **Every endpoint 417s.** All **23** `refuse_if_core_native`-guarded whitelisted endpoints
  (verify the count against the tree at PR time) raise `PasskeyServedByCore` → HTTP 417 when core
  is native. Enumerate them; do not spot-check.
- **Every hook no-ops.** All **8** dormant-gated handlers return without side effects when core is
  native: the `on_login` veto, `guard_system_settings`, `seed_sudo_window`, `clear_sudo_window`,
  `extend_bootinfo`, `cascade_delete_user_artifacts`, and the two `shims/*.website_context`.
- **No double authority.** With both the app (dormant) and native core present, assert there is
  exactly **one** `on_login` veto in effect, **one** sudo store, **one** `User.on_trash` cascade,
  **one** `/passkeys` renderer, and **one** session-minting endpoint set — the failure this shell
  exists to prevent.
- **Fresh install onto a native core is refused** in `before_install` (two authorities over the
  same tables).

### (c) `two_factor_registry_available()` probe flip (both directions)

`passkeys/install.py::two_factor_registry_available()` currently `return False` (pinned to a core
symbol Stage 1 introduces). Validate both legs:

- **Probe `False`** (no Stage-1 core): `sync_registry_fixture` (`after_install`/`after_migrate`)
  **removes** any `Passkey` `two_factor_method` Property Setter, and the second factor runs through
  the app's own dispatch (`passkeys/passkey.py::_dispatch_passkey_second_factor`, `:436`). Assert
  no `Passkey` option is present on `System Settings.two_factor_method`.
- **Probe `True`** (Stage-1 core present, not yet native): `sync_registry_fixture` **adds** the
  `Passkey` option via a `module="Passkeys"` Property Setter, and the factor dispatches through
  core's `two_factor_methods` registry (patch 01), **not** the app dispatch. Assert the option
  appears and the registry path is taken.
- Flip the probe in a test by monkeypatching the pinned `hasattr(frappe.twofactor, …)` both ways;
  assert the Property Setter is added/removed symmetrically and no `fixtures/` fixture is written
  (that would fight core's option list).

## Whole-PR gates (both stages)

The CI a maintainer's PR must clear, worth running locally before pushing:

- `commitlint` — conventional-commit title (`feat: …`).
- **docs link** — `.github/helper/documentation.py` fails a `feat:` PR with no docs link; file
  the docs PR in parallel.
- `pip-audit` over the new `webauthn` pin (Stage 2).
- server test suite + Cypress; `frappe/semgrep-rules`; `ruff`/`prettier`/`eslint`.
- **Never go stale:** respond to review within days — the 60+3-day stale bot is what killed
  #34181.
