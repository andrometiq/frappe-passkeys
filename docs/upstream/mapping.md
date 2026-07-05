# App → core mapping

Every `passkeys` app artifact, its core destination, and the **nature** of the move. Based on
the built app tree (`passkeys/`) and DESIGN-v1 §11. Core paths assume the Stage-0 default
placement (`frappe/core/…`, DocType names kept); if review picks `frappe/integrations/` or the
`User Passkey` rename, the destination path/table changes but the nature column does not.

**Nature legend:** **verbatim** = file moves, `frappe.*` imports already, zero logic change ·
**rename** = same code, module/module-path relabel · **fold** = merges into another core file ·
**shim** = app-phase-only glue, **deleted** on merge · **discard** = not needed in core.

## Python — engine & endpoints

| App artifact | Core destination | Nature |
|---|---|---|
| `passkeys/passkey.py` (guest login endpoints, `cascade_delete_user_artifacts`, session mint) | `frappe/passkey.py` | fold (into the single core module) |
| `passkeys/engine.py` (py_webauthn options/verify wrappers, crypto core) | `frappe/passkey.py` | fold |
| `passkeys/state.py` (ceremony / sudo / grant / uv-setup cache store) | `frappe/passkey.py` | fold |
| `passkeys/policy.py` (RP-ID / origin / UV / sign-count / BE-BS policy) | `frappe/passkey.py` | fold |
| `passkeys/session.py` (sudo-window semantics + grant consumer) | `frappe/passkey.py` | fold |
| `passkeys/api/registration.py` (`begin_registration`, `verify_registration`) | `frappe/passkey.py` | fold |
| `passkeys/api/credentials.py` (`list_credentials`, `rename_credential`, `delete_credential`, `set_passkey_only_login`) | `frappe/passkey.py` | fold |
| confirm API — `begin_confirmation` / `verify_confirmation` / `reauth_password` + `@passkey_protected` (DESIGN §7; app Phase 5, in progress) | `frappe/passkey.py` (public re-auth API) | fold |
| `passkeys/passkey.py::_dispatch_passkey_second_factor` (`:378`) + `_verify_second_factor_assertion`, `_reauthenticate_before_mint`, `_rearm_second_factor`, `fallback_to_otp` | `frappe/twofactor.py` — native `Passkey` provider via the Stage-1 registry (`issue`/`verify`) | **shim** (LDAP-shaped dispatch; deleted, logic re-homed natively) |

## Python — hooks, install, notifications

| App artifact | Core destination | Nature |
|---|---|---|
| `passkeys/auth_hooks.py::guard_system_settings` (reverse 2FA-floor guard) | `frappe/core/doctype/system_settings/system_settings.py` validate | fold (native validation) |
| `on_login` passkey-only veto (DESIGN §9.3) | `frappe/auth.py` / User validation | fold |
| `passkeys/session.py::seed_sudo_window` / `clear_sudo_window` (`on_session_creation`/`on_logout`) | `frappe/passkey.py` + core hook registration in `frappe/hooks.py` | fold |
| `passkeys/install.py` (`before_install` version floor, `CORE_NATIVE` refusal, uninstall lockout guard) | — | **discard** (a merged core needs no install-guard; the app keeps these while it exists as the v15/v16 vehicle) |
| `passkeys/install.py::sync_registry_fixture` + `_create/_remove_registry_property_setter` (the `Passkey` `two_factor_method` Property Setter) | `system_settings.json` `two_factor_method` gains `Passkey` natively | **shim** (Property Setter removed by the adoption patch) |
| `passkeys/install.py::two_factor_registry_available` (Stage-1 `hasattr` probe) | — | **shim** (feature-detection is moot once the app is dormant) |
| notifications / out-of-band emails (added/removed/flagged — DESIGN §1.3, not yet built) | `frappe/passkey.py` + `frappe/templates/emails/` | verbatim |
| AAGUID→provider snapshot (vendored JSON asset — DESIGN §1.3) | `frappe/passkey/…` static asset | verbatim |

## DocTypes

| App DocType | Core destination | Nature |
|---|---|---|
| `WebAuthn Credential` (`passkeys/passkeys/doctype/webauthn_credential/`, module `Passkeys`) | `frappe/core/doctype/webauthn_credential/` (module `Core`) | **rename** (module only; table `tabWebAuthn Credential` unchanged → zero row surgery) |
| `WebAuthn User Handle` (`…/webauthn_user_handle/`, module `Passkeys`) | `frappe/core/doctype/webauthn_user_handle/` (module `Core`) — **kept as a DocType** (real unique index on the handle; core keeps auth artifacts off `tabUser`) | **rename** (module only) |
| `Passkey Settings` (Single, `…/passkey_settings/`) | System Settings fields (`login_with_passkey`, `passkey_as_second_factor`, `passkey_rp_id`, `passkey_origins`, `passkey_max_per_user`, `passkey_notify_on_change`, …) | **fold** (Single dissolves; fieldnames were chosen to be the future System Settings names, so the adoption patch is a value-copy) |

## Templates / JS / portal

| App artifact | Core destination | Nature |
|---|---|---|
| `passkeys/shims/login_page.py` (`update_website_context` → conditional `web_include_js`) | `frappe/www/login.py` + `login.html` native slot (patch 03) | **shim** (deleted) |
| `passkeys/public/js/passkey_login.bundle.js` (conditional UI, button, 2FA step, uv-setup) | `frappe/public/js/` passkey bundle + `frappe/templates/includes/login/login.js` sections | fold |
| `passkeys/public/js/passkey_common.js` (JSON shim, b64url, ceremony helpers, Signal API) | `frappe/public/js/frappe/utils/` + passkey bundle | fold (cf. #34181's `utils.js` +40) |
| `passkeys/public/js/passkey_confirm.js` (confirm dialog helper) | passkey bundle | fold |
| `passkeys/public/js/passkey_desk.bundle.js` (User-form cards, nudge, `frappe.passkeys.*` — DESIGN §1.3) | `frappe/core/doctype/user/user.js` + Desk bundle | fold (cf. #34181's `user.js` +288) |
| `doctype_js` User-form section + `doc_events` `User.on_trash` cascade | `frappe/core/doctype/user/user.js` + `user.py` | fold |
| `www/passkeys.{html,py}` portal management page (DESIGN §1.3, not yet built) | `frappe/www/passkeys.{html,py}` | verbatim |
| `passkeys/translations/` guest-i18n endpoint (`get_app_translations`, `passkey.py:706`) | native guest translation delivery on develop; **stays app-only for v15/v16** | mostly **discard** on merge |

## Packaging / tests

| App artifact | Core destination | Nature |
|---|---|---|
| `pyproject.toml` `webauthn>=2.8,<3` pin | `pyproject.toml` `+ webauthn~=2.8` (one line) | verbatim |
| `passkeys/tests/*` (`test_passkey`, `test_login_api`, `test_second_factor`, `test_registration_api`, `test_credentials_api`, `test_engine_vectors`, `test_state`, `test_sudo_window`, `test_install`, cypress helpers) | `frappe/tests/test_passkey.py` + DocType tests + `cypress/` | verbatim (path fixes only — built on `IntegrationTestCase`/`FrappeAPITestCase` so they run unmodified after the move) |
| `passkeys/hooks.py` (coupling surface) | core hook registrations in `frappe/hooks.py` + native validation | fold / discard (the app-specific `before_install`/`CORE_NATIVE` lines are dropped) |
| — | `frappe/patches/vXX/adopt_frappe_passkeys_app.py` | **new** (~30 lines; possible only because tables + fieldnames are identical by construction) |

## What stays in the app forever

**Nothing.** The design goal is total collapse. What remains *in the app package* after a
passkey-native core exists is not core-bound functionality but the **dormant-shell + adoption
machinery** — `before_install` refusal, the `CORE_NATIVE` no-op switch across every hook, the
`PasskeyServedByCore` typed refusal on every endpoint, and `sync_registry_fixture`'s
Property-Setter cleanup. That code exists so a site that installed the app *before* the merge can
`bench update` onto a native core without a double-authority conflict; it is upgrade scaffolding,
not a permanent app surface, and the app is never a fresh install on top of a native core.
