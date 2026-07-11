# App → core mapping

Every `passkeys` app artifact, its core destination, and the **nature** of the move. Based on
the built app tree (`passkeys/`). Core paths assume the Stage-0 default
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
| `passkeys/confirm.py` — `begin_confirmation` / `verify_confirmation` / `reauth_password` + `@passkey_protected` (built; canonical re-auth namespace + password leg) | `frappe/passkey.py` (public re-auth API) | fold |
| `passkeys/passkey.py::_dispatch_passkey_second_factor` (`:436`) + `_verify_second_factor_assertion`, `_reauthenticate_before_mint`, `_rearm_second_factor`, `fallback_to_otp` | `frappe/twofactor.py` — native `Passkey` provider via the Stage-1 registry (`issue`/`verify`) | **shim** (LDAP-shaped dispatch; deleted, logic re-homed natively) |

## Python — hooks, install, notifications

| App artifact | Core destination | Nature |
|---|---|---|
| `passkeys/auth_hooks.py::guard_system_settings` (reverse 2FA-floor guard) | `frappe/core/doctype/system_settings/system_settings.py` validate | fold (native validation) |
| `on_login` passkey-only veto | `frappe/auth.py` / User validation | fold |
| `passkeys/session.py::seed_sudo_window` / `clear_sudo_window` (`on_session_creation`/`on_logout`) | `frappe/passkey.py` + core hook registration in `frappe/hooks.py` | fold |
| `passkeys/install.py` (`before_install` version floor, `CORE_NATIVE` refusal, uninstall lockout guard) | — | **discard** (a merged core needs no install-guard; the app keeps these while it exists as the v15/v16 vehicle) |
| `passkeys/install.py::sync_registry_fixture` + `_create/_remove_registry_property_setter` (the `Passkey` `two_factor_method` Property Setter) | `system_settings.json` `two_factor_method` gains `Passkey` natively | **shim** (Property Setter removed by the adoption patch) |
| `passkeys/install.py::two_factor_registry_available` (Stage-1 `hasattr` probe) | — | **shim** (feature-detection is moot once the app is dormant) |
| `passkeys/notifications.py` — out-of-band change emails (add/remove/disable/flag) + risk-event Activity-Log telemetry + admin-change owner notices; **built** | `frappe/passkey.py` (bodies stay inline `_()`-wrapped, NOT `templates/emails/`) | fold |
| `passkeys/boot.py` — Desk `extend_bootinfo` flag + per-user enrollment-nudge state (`__passkeys` Defaults rows) + `record_nudge_event`; **built** | `frappe/passkey.py` + core boot registration in `frappe/boot.py` / `frappe/hooks.py` | fold |
| dormant-shell layer — `install.is_core_native`/`dormant` (`find_spec("frappe.passkey")`, memoized), `passkey.refuse_if_core_native` → 417 `PasskeyServedByCore` on all 18 whitelisted endpoints, all 7 hook entry points no-op; **built** | — | **discard** (upgrade scaffolding whose whole job is to no-op *on* a passkey-native core; gone once core is native) |
| `passkeys/aaguid.py` + `passkeys/public/aaguid-map.json` — vendored community AAGUID→provider snapshot + loader (frappe-free / webauthn-free, `lru_cache`); **built** | `frappe/passkey.py` loader + `frappe/passkey/…` static asset | fold (loader) + verbatim (JSON asset moves) |

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
| `passkeys/shims/portal_nudge.py` (`update_website_context` → the self-gating portal bundle + a `frappe.boot.passkeys` bridge on **every** authenticated website render — website boot omits `extend_bootinfo`); **built** | native portal boot + `web_include_js` slot | **shim** (deleted — website nudge becomes native) |
| `passkeys/public/js/passkey_login.bundle.js` (conditional UI, button, 2FA step, uv-setup) | `frappe/public/js/` passkey bundle + `frappe/templates/includes/login/login.js` sections | fold |
| `passkeys/public/js/passkey_common.js` (JSON shim, b64url, ceremony helpers, Signal API) | `frappe/public/js/frappe/utils/` + passkey bundle | fold (cf. #34181's `utils.js` +40) |
| `passkeys/public/js/passkey_confirm.js` (confirm dialog helper) | passkey bundle | fold |
| `passkeys/public/js/passkey_desk.bundle.js` (User-form cards, nudge, `frappe.passkeys.*`) | `frappe/core/doctype/user/user.js` + Desk bundle | fold (cf. #34181's `user.js` +288) |
| `passkeys/public/js/passkey_portal.bundle.js` (portal `/passkeys` management cards + `maybeNudgeBanner`; self-gates on a `#passkey-portal-root` mount) | `frappe/public/js/` passkey bundle + portal template | fold |
| `passkeys/public/js/passkey_manage_common.js` (shared Desk+portal management logic: banners, origins mirror, RP-ID one-way-door revert) | `frappe/public/js/frappe/utils/` + passkey bundle | fold |
| `passkeys/public/js/passkey_settings.js` (Passkey Settings form — RP-ID one-way-door confirm gating the save, cross-flag data) + `passkeys/public/css/passkey_manage.css` | `frappe/core/doctype/passkey_settings/…` (folds with the Settings fields) + Desk CSS | fold |
| `doctype_js` User-form section (`user_passkeys.js`) + `doc_events` `User.on_trash` cascade | `frappe/core/doctype/user/user.js` + `user.py` | fold |
| `passkeys/www/passkeys.{html,py}` portal management page; **built** | `frappe/www/passkeys.{html,py}` | verbatim |
| `passkeys/translations/` guest-i18n endpoint (`get_app_translations`, `passkey.py:766` — version-keyed `Cache-Control`) | native guest translation delivery on develop; **stays app-only for v15/v16** | mostly **discard** on merge |

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
