# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each release branch carries its own
version: the first public release is 15.0.0 (`version-15`, for Frappe v15) and 16.0.0
(`version-16`, for Frappe v16), with the same features and fixes.

## [Unreleased]

## [15.0.0] / [16.0.0] — 2026-09-24 — First public release

### Added

- Final-login enforcement for enrolled passkey second-factor users, including alternate core login
  paths and a one-time, user-bound OTP fallback handoff.
- Database serialization for credential verification, UV completion, registration caps,
  passkey-only account floors, and passkey-mode changes.
- Site-bound, HMAC-authenticated credential exports with atomic private-file writes and strict
  restore validation.
- Explicit action labels and safe parameter summaries for passkey confirmation dialogs.
- `@passkey_protected` requires a passkey by default; confirming with a password is an explicit
  per-action opt-in (`allow_password_fallback=True`). **Integrators:** pass it on any custom action
  that should still accept a password.
- A refused registration, confirmation or password re-auth raises `CeremonyFailed` (401) and keeps
  the user signed in, so they can retry.
- Passkey management, confirmation, password re-auth and `@passkey_protected` actions require a
  signed-in browser session; a request authenticated by an API key or OAuth token is refused with
  `BrowserSessionRequired` (403), so it can never open a sudo window or obtain a confirmation grant.
  Token-authenticated API requests are not subject to passkey sign-in checks, as with Frappe's
  two-factor authentication.
- Server-side format checks for the Android fingerprint, iOS Team ID and iOS Bundle ID fields.
- Shared, site-scoped action policy publication for deterministic confirmation across workers.
- Pinned-input release CI, data-bearing lifecycle checks, JavaScript unit gates, secret scanning,
  and a separate moving-upstream compatibility workflow whose failures remain visible.
- Private security-reporting policy.

### Changed

- The Passkey Settings form is reorganized into Login Modes, Relying Party, Mobile Apps,
  Enrollment, Security, and Notifications tabs.
- Role-wide enforcement exemptions are removed in favor of per-user temporary exemptions and
  console recovery.
- RP IDs no longer imply trust in `https://<rp_id>`. Only a compatible configured `host_name`
  origin and explicitly listed Passkey Origins are accepted. **Action required before upgrading an
  already-enabled site:** confirm `host_name` or an explicit Passkey Origin resolves within the RP
  ID scope first, or the resolved origin set can become empty and every ceremony fails closed (a
  generic sign-in error for users, with a structured log line for operators) until the settings
  are fixed — see the [upgrade note](docs/install.md#upgrade).
- Administrator remains exempt from the per-user passkey-only password veto, but an Administrator
  enrolled in passkey second-factor mode must complete that factor.
- Passkey second-factor ceremonies detect password changes between legs without normally retaining
  the password in ceremony state.
- Enforcement deferrals are idempotent per user session.
- Android certificate fingerprints must contain exactly 64 hexadecimal characters.
- Native-core dormancy now requires an explicit handover capability marker; module presence alone
  cannot silence an installed app.
- Browser management, confirmation, headless, portal, recovery, and unsupported-device states now
  use the same server-owned contracts.
- Legacy unsigned credential exports require an explicit, operator-reviewed import opt-in.

### Fixed

- Concurrent nudge events preserve opt-out, and enforcement deferrals read current grace state.
- Per-user nudge and grace state is read by exact key from the database, so a user without a row
  no longer reads a look-alike user's state (`mary-jane@` vs `mary_jane@`).
- Nudges count only after rendering, and both login modes being off suppresses nudge and upsell
  eligibility. A failed "Don't ask again" keeps the prompt open with a visible error so the user
  can retry.
- Incapable devices under Degrade to Nudge share the ordinary cap, cooldown and opt-out on
  Desk and portal; the settings form now shows those two fields under Enforce + Degrade to Nudge.
- User renames preserve nudge, grace and notification state, including case-only renames; merges
  keep target values. Merging two users who both have passkeys is refused with a clear message
  instead of a database duplicate-entry error.
- Stale hybrid upsell hints are consumed even when capped and cleared on login initialization.
- Conditional creation falls back to the eligible visible nudge whenever it does not end in a
  server-verified credential (including a rejected verify or a network error), except on abort.
- The portal is localized, and headless `login()` resolves `{ok: false, reason: "network"}` when
  `begin_login` itself fails instead of rejecting.
- A manually dispatched CI run no longer tolerates a failing pinned develop leg; only the scheduled
  upstream-drift run may.
- Server CI rejects failed, empty, or unrecognized test summaries even when the framework test
  command exits successfully.
- Enabling either login mode now checks the actual ceremony-engine imports in an isolated process,
  catching installed but broken crypto dependencies without importing them into login hooks.
- Registration on browsers without native credential JSON serialization now sends an attestation
  response for explicit, headless, and conditional enrollment.
- Enforcement reporting respects the current server verdict, and concurrent incapable-device
  reports no longer send duplicate administrator advisories within the notification window.
- Guest translation catalogs are not reused from an earlier request language.
- First-factor passkey retries now replace spent or near-expiry ceremonies before prompting,
  preserve each gesture's exact state/options pair, and recover across repeated failures and bfcache
  restores without a page reload.

### Security

- Core-login classification respects command dispatch precedence: an email-link or other diverted
  request cannot obtain password-grade management sudo or consume an OTP fallback marker merely
  by using the login URL.
- First-factor verification failures now collapse to the uniform `AuthenticationError` wire type
  instead of exposing the engine's cause class to guests.
- Privileged users (`System Manager`) are now inside enforcement scope by default, with no standing
  role exemption. This matches industry practice and Frappe core's removal of the Administrator 2FA
  exemption.
- Test-only WebAuthn helpers require a test runner, or a System Manager on a site with both
  `developer_mode` and `allow_tests` enabled. The two guest-callable UI-test helpers (session wipe
  and a capped slow echo) require both flags too; the deterministic-cookie flag alone no longer
  enables them. Every helper except the slow echo is POST-only.
- An impersonated session can no longer register a passkey, so an Administrator impersonating a
  user cannot leave behind a credential that user never created.
- System Settings refuses to disable username/password login while Passkey as Second Factor is
  the only passkey mode (the Passkey Settings side already refused the same combination). Both
  sides, and the two-factor floor, check each other under row locks, so concurrent saves of the two
  settings pages cannot together commit an unsafe combination.
- `@passkey_protected` rejects `bind_params` names missing from the decorated function's
  signature at decoration time, and reads bound names passed through `**kwargs`; previously both
  bound `None`, so one grant covered any payload. Naming the `**kwargs` parameter itself binds the
  whole mapping.
- Assertion counters are reclassified under row locks before sessions or grants are minted,
  rejecting duplicate nonzero counter replays.
- Credential import refuses unsigned files by default, modified or cross-site v2 files,
  structurally inconsistent rows, and unreviewed live-data merges.
- Minimum supported Frappe is a per-major-line floor (v15 ≥ 15.108.0, v16 ≥ 16.18.3) that excludes
  releases exposed to CVE-2026-47194 (host-header poisoning of magic/passwordless login links);
  enforced by the `before_install` version check.

[Unreleased]: https://github.com/Andrometiq/frappe-passkeys/compare/v16.0.0...develop
[15.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.0
[16.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.0
