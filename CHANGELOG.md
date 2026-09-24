# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each release branch carries its own
version: the first public release is 15.0.0 (`version-15`, for Frappe v15) and 16.0.0
(`version-16`, for Frappe v16), with the same features and fixes.

## [Unreleased]

## [15.0.0] / [16.0.0] — 2026-09-24 — First public release

### Added

- Passwordless sign-in with discoverable passkeys: username-field autofill (conditional UI), a
  "Sign in with a passkey" button, and cross-device sign-in by QR code.
- Passkey as a second factor after the password, in Frappe's own two-factor flow, with an optional
  one-time-code fallback.
- `@passkey_protected` for any whitelisted method: a single-use confirmation grant bound to the
  user, session, action and the arguments listed in `bind_params`. A passkey is required unless an
  action opts in with `allow_password_fallback=True`. Dialogs show an explicit action label and only
  the parameters declared safe to display.
- Enrollment nudges with a prompt cap and cooldown, and a post-login requirement for no one,
  selected roles, or all users. System Managers can be required on top of that scope. A blank
  start date means immediately; before the date, in-scope users are nudged. Everyone outside
  the scope is nudged or left alone. Grace sign-ins, per-user exemptions and an admin grace
  reset are included. Phone and QR enrollment is always offered.
- Self-service management at `/passkeys` and on the User form, including a per-user passkey-only
  sign-in switch.
- A security-posture panel on Passkey Settings, console recovery commands, and site-bound,
  HMAC-signed credential export and restore.
- Android Digital Asset Links and iOS `apple-app-site-association` files for native apps.
- The `frappe.passkeys.headless` JavaScript API and documented REST endpoints for custom UIs.

### Security

- Every login mode ships off. The RP ID and origins come from pinned configuration — a `host_name`
  origin within the RP ID scope plus explicitly listed Passkey Origins — never from request
  headers, and an RP ID never implies trust in `https://<rp_id>`.
- Passwordless sign-in and action confirmation require user verification; a credential first
  registered without it needs the password once before it can sign in alone.
- A repeated non-zero signature counter is always rejected; a regression flags the passkey and
  emails its owner, or is rejected when so configured. Counters are reclassified under row locks
  before any session or grant is minted.
- When the user is known before the ceremony, a returned `userHandle` must belong to that user
  (WebAuthn L3 §7.2), and the credential must be in that ceremony's allow-list.
- Enrolled second-factor users are held at the final login hook on every core login path, not
  only on the login page; the one-time-code fallback is a single-use, user-bound handoff.
- Passkey management, confirmation, password re-auth and `@passkey_protected` actions require a
  signed-in browser session; API-key or OAuth requests get `BrowserSessionRequired` (403) and never
  open a sudo window or obtain a grant. Token-authenticated API requests are not subject to passkey
  sign-in checks, as with Frappe's two-factor authentication.
- A refused registration, confirmation or password re-auth raises `CeremonyFailed` (401) and keeps
  the user signed in; guest sign-in failures share one uniform error type.
- An impersonated session cannot register a passkey.
- Passkey Settings and System Settings check each other's floors under row locks, so concurrent
  saves cannot together disable the two-factor backstop or every login path.
- Guest endpoints are rate-limited per IP and signed-in endpoints per user. Test-only helpers need a
  test runner, or a System Manager on a site with `developer_mode` and `allow_tests`.
- Native-core handover requires an explicit capability marker; module presence alone never silences
  the app.
- Private security reporting (see `SECURITY.md`).

[Unreleased]: https://github.com/Andrometiq/frappe-passkeys/compare/v16.0.0...develop
[15.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.0
[16.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.0
