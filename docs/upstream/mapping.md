# Proposed app-to-core mapping checklist

> This is an inventory for an upstream design review. Destinations are proposals. Re-map the app and
> current core tree at the target ref before deciding that anything can move unchanged.

Use four outcomes during that review:

- **Port:** preserve a behavior contract in native core code after code-grounded review.
- **Fold:** integrate behavior into an existing core owner rather than copying a module.
- **Replace:** core already has a reviewed equivalent; prove parity before dropping the app path.
- **Discard:** app lifecycle/shim code has no role after a validated handover.

## Authentication and policy

| App surface | Proposed core owner | Review checklist |
|---|---|---|
| `passkeys/passkey.py`, `ceremony.py`, `errors.py`, `engine.py`, `state.py`, `policy.py` | Native passkey service | Preserve exact origins, binder, UV, counter/backup flags, keyed password version, one-time state, uniform typed errors (`errors.py` class names are the wire `exc_type`), and locked verification (User row before Credential row). Keep the isolated, time-bounded enablement probe in a core port. |
| `passkeys/api/registration.py`, `api/credentials.py` | User credential service | Preserve session-derived identity, global credential uniqueness, registration cap locks, ownership, last-credential floor, and passkey-only grant policy. |
| `passkeys/confirm.py`, `session.py` | Core re-auth/confirmation service | Preserve single-use user+session+action+payload grants, consume-before-action, password fallback policy, and `display_label`/`display_params`. |
| `passkeys/auth_hooks.py` | Core login completion | Preserve alternate-path veto, one-time OTP marker, narrow Administrator exemption, and two-factor floor. Do not depend on app-only request flags without a native replacement. |
| `passkeys/well_known.py` | Core `/.well-known/` routing | Validate exact SHA-256 fingerprints, bare JSON/no redirect, one-hour cache, and native route ownership. |
| `passkeys/notifications.py`, `posture.py` | Core security notifications/settings UI | Re-evaluate copy and event ownership; preserve security-relevant notices and avoid treating adoption UI as an auth gate. |

## Data and settings

| App surface | Proposed treatment | Migration checklist |
|---|---|---|
| `WebAuthn Credential` | Port or migrate to the final core credential DocType | Preserve credential IDs, public keys, sign counters, backup flags, UV state, owner, enabled/flagged state, metadata, and uniqueness. |
| `WebAuthn User Handle` | Port or migrate to the final core handle model | Preserve immutable user/handle mapping and passkey-only state. |
| `Passkey Settings` | Fold into the core settings owner selected by maintainers | Copy every scalar deliberately; validate RP/origin semantics after copy. Do not infer compatibility from matching field names. |
| `Passkey Enforcement Role` child rows and per-user exemptions | Re-parent selected-role rows; preserve exemptions | Preserve `Passkey Enforcement Role` rows and the `{user}_passkey_exempt` rows under `__passkeys`. There is no role-wide exemption table. Native recovery also needs an operator-only console equivalent. |
| `__passkeys` DefaultValue rows | Migrate or intentionally reset by type | Separate nudge/grace state from ephemeral Redis state; preserve User rename/merge handling and current locking reads when folding events. |
| Export schema v2 | Migration/recovery input only if core implements it | Verify site binding and HMAC before use; define field mapping; default to empty destination; review any merge. |

## UI and integration

| App surface | Proposed core owner | Review checklist |
|---|---|---|
| Login, Desk, portal, headless, confirmation, and management bundles | Native core bundles/components | Port behavior and accessibility; do not assume app DOM anchors or global names are stable core APIs. |
| `shims/login_page.py`, `shims/portal_nudge.py` | Replace with native render/boot integration | Delete only after native surfaces are tested with the app still installed. |
| `/passkeys` page and User-form integration | Core User/security UX | Decide the canonical surface, permissions, portal behavior, and redirect compatibility. |
| AAGUID snapshot/loader | Optional display data | Keep display-only and non-authoritative; record any vendored snapshot as a dated artifact. |
| Translations | Core translation pipeline | Verify guest login delivery and every new confirmation display label. |

## App lifecycle after native release

- Fresh install remains blocked when `frappe.passkey` exists.
- Installed-app dormancy remains **off** until core advertises the exact handover marker.
- Before defining the marker, enumerate every app hook, endpoint, route, scheduled/background path,
  DocType event, cache namespace, and asset injection; prove each is dormant or removed.
- Run install, upgrade, coexistence, migration, uninstall, reinstall/import, rollback, and backup-
  restore scenarios on each supported release line.
- Keep export/import tooling until operators have a tested native recovery path; do not discard it
  merely because native schema exists.

## PR-time output

The upstream PR should replace this proposal with a dated matrix containing the exact app commit,
core commit, chosen destinations, migration behavior, and test evidence. Counts and hashes belong in
that immutable review snapshot, not in this evergreen design document.

The enrollment boot contract includes `enforcement.enforcing` (the site requires a passkey
from someone) and `enforcement.effective` (`off`, `nudge`, or `enforce` for this user).
Phone/QR enrollment is always offered, so the verdict has no hybrid switch.
`enforcement.degrade_nudge_eligible` applies the ordinary nudge opt-out, cap and cooldown
to in-scope, unenrolled users under Degrade. Both Desk and portal require this explicit
verdict for incapable-device nudges.

The stock OTP completion submits no `usr` and clears the site's non-persistent cache before
`on_login`. Preserve the `passkeys:otp-fallback:` prefix through `persistent_cache_keys` (or its
native equivalent); keep TTL expiry and atomic consumption. Other ceremony, uv-setup, grant,
and sudo flows do not require a core OTP login between mint and consume. Concurrent cache
clears may still cancel them safely, requiring a fresh ceremony or confirmation.

Confirmation clients map `CeremonyExpired` without relying on `_server_messages` and reuse the
shared timeout copy. App-action refusals say “This action requires a signed-in browser session.”
and “Confirm it's you to continue.” Management gates keep their management-specific copy.
Last-credential guards retain both policy checks and name the setting that caused the refusal.
The site-wide refusal directs users to add another enabled passkey or turn off
Disable Username/Password Login in System Settings.
