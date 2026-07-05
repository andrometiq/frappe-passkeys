# Upstreaming passkeys into `frappe/frappe` — merge strategy

This directory is the **clear path to core**: the concrete plan and the actual patches to move
passkey (WebAuthn) authentication from the standalone `passkeys` app into `frappe/frappe`, with
no loss of behaviour and a disposable migration shim.

All core citations are repo-relative `file:line` at these audited SHAs (the pins the app was
built against):

| Branch | SHA | Version |
|---|---|---|
| `develop` | `9b48af62aff88522638e38b1f4738e79ce0902fd` | 17.0.0-dev |
| `version-16` | `9a8daf343db69a0127f470bad8be0af192cd80c8` | 16.25.0 |
| `version-15` | `588e443808206a7bfe87429c5a55e16016ec7840` | 15.113.4 |

**All PRs target `develop` only.** Mergify auto-closes outsider PRs to `version-*`
(`.mergify.yml`); backports are maintainer-label-driven. The app remains the v15.107+/v16
delivery vehicle indefinitely; core lands in v17.

---

## Prior art (do not re-derive — build on it)

- **PR [#34181](https://github.com/frappe/frappe/pull/34181)** ("passkey authentication",
  Sept–Nov 2025) — the blessed blueprint. 16 files, +1007/−1, MIT, maintainer-reviewed with
  **no conceptual objection**, closed by the stale bot after 60+3 days of silence — died of
  neglect, not rejection. Its file layout (`DocType` + `py_webauthn` + `login_as` session mint +
  System Settings toggle + registration from the User form) is a de-facto maintainer-approved
  skeleton. Its WebAuthn-policy flaws (guest broadcast of every credential id; UV off at login;
  no rate limiting; swallowed errors in HTTP-200; fresh `LoginManager()`; challenge deleted only
  on success; naïve RP-ID; no 2FA-policy answer; client-supplied user identity) are the review
  spec of what core will *not* accept — every one is fixed in this app.
- **Issue [#37486](https://github.com/frappe/frappe/issues/37486)** (native passkeys, 2026-02,
  open/unassigned) — the issue the Stage-2 PR carries `closes`.
- **Issue [#4252](https://github.com/frappe/frappe/issues/4252)** (FIDO2 second factor, 2017,
  still open) — closed by the Stage-1 PR.
- **PR [#19363](https://github.com/frappe/frappe/pull/19363)** (email-link login) — the most
  recent successfully-merged "add a login method"; the file-for-file rhyme (System Settings
  checkbox + guest endpoints + `login.js` section + `test_auth.py` integration test).

**Stake the claim first (Stage 0):** a design comment on #37486 linking #4252 / #34181,
declaring the two-PR plan, and asking the two `git mv`-cheap placement questions — module home
(`frappe/core` vs #34181's `frappe/integrations`) and DocType naming (`WebAuthn Credential` vs
#34181's `User Passkey`). Verify the live #34181 review thread before quoting it (two research
reports sampled its comments differently).

---

## The two-stage PR plan

**Why staged:** the passkey *second factor* (J4, #4252) is the one seam that today needs
monkeypatching two import-binding sites (`frappe/auth.py:18-23` imports the 2FA functions by
name; `ldap_settings.py:22` re-imports them) because 2FA method dispatch is a closed
`OTP App | SMS | Email` set hardwired in `frappe/twofactor.py`. That capability is independently
valuable (any app could register a 2FA method), reviewable in one sitting, and de-risks the big
PR. Splitting it means Stage 2 never has to argue two things at once.

### Stage 1 — `feat: pluggable two-factor methods` (~45 lines + tests)

Closes #4252. A `two_factor_methods` registry hook in `frappe/twofactor.py`: an app registers a
method by name supplying `{is_configured(user), issue(user, tmp_id) → verification_obj,
verify(login_manager, otp, tmp_id) → bool}`. Dispatch is consulted inside the three existing
functions — `authenticate_for_2factor`, `get_verification_obj`, `confirm_otp_token` — behind a
`get_two_factor_method_provider()` resolver; the built-in `OTP App`/`SMS`/`Email` paths are
**byte-identical** when no provider is registered. Rides along: the
`validate_user_pass_login` allowlist +1 (patch 02) and the `autocomplete="username webauthn"`
token (patch 04) go with whichever PR lands first. See
[`patch-01-two-factor-methods-registry.md`](./patch-01-two-factor-methods-registry.md).

### Stage 2 — `feat: passkey (WebAuthn) authentication`

Closes #37486. The whole app collapses into core (mapping in [`mapping.md`](./mapping.md)):
`frappe/passkey.py` (engine + endpoints), the two DocTypes (module rename only), the System
Settings fields, the native `Passkey` 2FA provider (retiring the app's second-factor dispatch
onto the Stage-1 registry), the native login-page button + bundle (retiring the injection shim —
patch 03), and one `post_model_sync` adoption patch.

### How the app *feature-detects* Stage 1 to prefer the native path

The app declares `two_factor_methods` **statically and unconditionally** in `hooks.py` — inert
on v15/v16/pre-Stage-1 develop, because core there never reads that hook. It must therefore
**never** detect Stage 1 via `frappe.get_hooks("two_factor_methods")`: the app's own static
entry would self-poison the probe (it would always look "present"). Detection is keyed to a
**core symbol introduced by Stage 1** — `hasattr(frappe.twofactor, "get_two_factor_method_provider")`
(pinned in `passkeys/install.py::two_factor_registry_available()`, currently a `return False`
placeholder awaiting the merged symbol name). When present, `sync_registry_fixture`
(`after_install`/`after_migrate`) programmatically adds the `Passkey` option to
`System Settings.two_factor_method` via a `module="Passkeys"` Property Setter and the second
factor runs through core's registry; when absent, the app's own LDAP-shaped dispatch
(`passkeys/passkey.py::_dispatch_passkey_second_factor`, `:378`) carries it. Never a
`fixtures/` fixture (that would fight core's own option list); never a version-string check.

---

## How the app collapses into core (the disposable shim layer)

The merge is "move files + drop the shim" **only because the app was built in core's image**:
identical DocType schema, table names, and fieldnames chosen up-front to be the future core
names (`WebAuthn Credential`, `WebAuthn User Handle`, `login_with_passkey`,
`passkey_as_second_factor`, …). That makes the app→core data migration an in-place module flip,
not a copy:

```python
# frappe/patches/vXX/adopt_frappe_passkeys_app.py  (~30 lines, post_model_sync)
# Runs only if the passkeys app is installed on this site.
#   1. Reassign `WebAuthn Credential` + `WebAuthn User Handle` DocTypes: module "Passkeys" -> "Core".
#      Same table names (tabWebAuthn Credential / tabWebAuthn User Handle) => ZERO row surgery,
#      no INSERT...SELECT — the rows are already in the destination tables by construction.
#   2. Copy Passkey Settings (Single) field values into the new System Settings fields.
#   3. Remove the app's `Passkey` two_factor_method Property Setter (now a core-native option).
#   4. Mark the app dormant (see below).
```

> Note: an `INSERT…SELECT` migration is only needed **if** Stage-0 lands the maintainer's DocType
> **rename** (`WebAuthn Credential` → `User Passkey`), which changes the table name. Under the
> app's own names it degenerates to the module reassignment above. Either is trivial because the
> **column set is identical by construction** — that is the whole point of building in core's image.

**The shim layer that is deleted on merge** is small and explicitly isolated (enforced in review:
nothing outside it may reference app-only mechanics):

- `passkeys/shims/login_page.py` — the `update_website_context` hook that conditionally appends
  the login bundle to `/login`. Retired by patch 03 (core renders the button + bundle natively).
- The app's second-factor dispatch (`passkeys/passkey.py::_dispatch_passkey_second_factor`) —
  retired by Stage 1's registry (the logic moves into a native `Passkey` provider in
  `frappe/twofactor.py`).
- `passkeys/passkeys/doctype/passkey_settings/` (the app-only Single) — dissolves into the
  System Settings fields it was schema-mirroring.

**The dormant-shell contract** (the app left installed on a passkey-native core): dormancy is a
single cached runtime switch `CORE_NATIVE = importlib.util.find_spec("frappe.passkey")`. When
true, every hook no-ops at entry (the `on_login` veto, sudo seeding, `doc_events`, bootinfo, the
website-context shim), every app endpoint raises typed `PasskeyServedByCore`, and
`sync_registry_fixture` removes the app's Property Setter — because "disable the two shims"
alone would leave the app's `on_login` veto racing core's, a parallel sudo store, a double
`on_trash` cascade, a shadowed `/passkeys`, and two session-minting endpoint sets. Fresh install
onto a native core is **refused** in `before_install` (two authorities over the same tables).

---

## The four core patches (this directory)

| # | File | Target (develop) | Size | Purpose |
|---|---|---|---|---|
| 01 | [`patch-01-two-factor-methods-registry.md`](./patch-01-two-factor-methods-registry.md) | `frappe/twofactor.py` | +~45 / −~4 | pluggable 2FA registry (Stage 1) |
| 02 | [`patch-02-disable-user-pass-login-validator.md`](./patch-02-disable-user-pass-login-validator.md) | `frappe/core/doctype/system_settings/system_settings.py:182-194` | +1 / −1 (+1 msg) | passkeys as a surviving login method (D9) |
| 03 | [`patch-03-login-page-context-template.md`](./patch-03-login-page-context-template.md) | `frappe/www/login.py`, `login.html`, `login.js` | +~40 | native login-page slot + bundle (retires the shim) |
| 04 | [`patch-04-autocomplete-webauthn-token.md`](./patch-04-autocomplete-webauthn-token.md) | `frappe/www/login.html:23` | 1 token | conditional-UI autofill (S6) |

Validation for each is in [`VALIDATE.md`](./VALIDATE.md). The full app-file → core-destination
surface (verbatim move / rename / shim-only / discarded, and what stays in the app forever) is in
[`mapping.md`](./mapping.md).

---

## Open questions (each with a proposed default — none block the plan)

1. **DocType module + naming (Stage 0).** `frappe/core/doctype/` (passkeys are core auth, like
   `twofactor.py`) vs #34181's `frappe/integrations/`; `WebAuthn Credential` vs `User Passkey`.
   **Default:** propose `frappe/core` + `WebAuthn Credential` in the #37486 comment; both are
   `git mv`-cheap, so defer to the maintainer's call — but ask *before* Stage 2 so the adoption
   patch is written against the final table name.
2. **The Stage-1 registry consult-symbol name.** The app's feature-detection is pinned to
   `frappe.twofactor.get_two_factor_method_provider` (patch 01). If review renames it, the app's
   one-line `two_factor_registry_available()` probe changes with it. **Default:** name it
   `get_two_factor_method_provider` in the Stage-1 PR; keep the app probe a single `hasattr` so
   the rename cost is one line.
3. **`py_webauthn` pin.** #34181 shipped `webauthn~=2.7`; the app pins `>=2.8,<3` (2.8 is the
   floor that co-installs with frappe's `cryptography`/`pyOpenSSL`; 3.x conflicts with every
   branch tip). **Default:** pin `webauthn~=2.8` in `pyproject.toml` on merge and justify it in
   the PR body (curated-pins culture), re-checking the then-current 2.x floor at PR time.
4. **Bundle Stage 1 + Stage 2 or keep them separate PRs.** **Default:** separate, Stage 1 first —
   it closes #4252 on its own, is reviewable in one sitting, and de-risks the large PR. Only
   bundle if a maintainer explicitly asks to see them together.
