# How to validate each patch

The core tests/checks a maintainer would run to confirm each patch is additive and correct.
Run inside a frappe bench with a test site (`bench --site test_site …`). SHAs as in
[`README.md`](./README.md).

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

## Patch 04 — autocomplete token

Pure markup. `curl -s http://test_site:8000/login | grep 'id="login_email"'` shows
`autocomplete="username webauthn"`. No unit test; covered incidentally by the patch-03 Cypress
conditional-UI spec (autofill only surfaces when the token is present). Confirm the HTML still
validates (no lint regression).

## Whole-PR gates (both stages)

The CI a maintainer's PR must clear, worth running locally before pushing:

- `commitlint` — conventional-commit title (`feat: …`).
- **docs link** — `.github/helper/documentation.py` fails a `feat:` PR with no docs link; file
  the docs PR in parallel.
- `pip-audit` over the new `webauthn` pin (Stage 2).
- server test suite + Cypress; `frappe/semgrep-rules`; `ruff`/`prettier`/`eslint`.
- **Never go stale:** respond to review within days — the 60+3-day stale bot is what killed
  #34181.
