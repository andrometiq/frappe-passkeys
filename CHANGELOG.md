# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each release branch carries its own
version: the first public release is 15.0.0 (`version-15`, for Frappe v15) and 16.0.0
(`version-16`, for Frappe v16), with the same features and fixes.

## [Unreleased]

### Upgrade notes

- A user signed in during the update may be asked to confirm it's them once more before managing
  passkeys or confirming an action.
- Disabling or deleting a passkey now signs its owner out: everywhere when it's someone else's,
  everywhere but the session in use when it's your own.

### Added

- A [Quickstart](docs/quickstart.md): five steps from install to your first passkey sign-in.
- Each Passkey Settings tab has a "Learn more" link to its part of the settings guide.
- A [Glossary](docs/glossary.md) of the words the settings and docs use.
- [Using passkeys](docs/using-passkeys.md), a page to send your users, and a
  [Troubleshooting](docs/troubleshooting.md) page keyed by the messages people see.
- System Managers now see new releases of this app in Frappe's update notice.
- [RELEASES.md](RELEASES.md): which line to install, what a version number means, and what counts as
  public API. SECURITY.md says how fast high and critical issues are fixed and what isn't a
  vulnerability.
- Every docs page links to the bug-report form.
- Before you save a change to who must use a passkey, Passkey Settings shows how many users without
  one it would affect. Saving never waits for this count, and it stays quick on sites with tens of
  thousands of users.

### Changed

- On a new install, Passkey Settings shows one line, "Passkeys are off. To turn them on, follow the
  Quickstart.", instead of three stacked notices, a security-posture card and a pop-up on save.
- The "passkey removed" email says who removed it and asks the user to delete it from their phone,
  computer or password manager too.
- Passkey emails name the address users open, not the server's internal site name.
- The flagged-passkey email says it plainly: the passkey may have been copied, and what to do.
- The "passkey added" email says when the browser saved the passkey on its own after a password
  sign-in, and the added and flagged emails say where to remove a passkey: the My Passkeys page.
- Disabling or deleting a passkey signs its owner out, so a lost or stolen device loses its
  session ([details](docs/recovery.md#someone-may-be-using-the-account-right-now)).
- The Remove passkey dialog says your other devices will be signed out.

### Security

- Session ids are no longer kept in the app's Redis data, so a backup or monitoring tool can't see
  them.
- With Conditional Create off, the server now refuses a passkey the browser tries to save on its
  own; before, only the browser checked the setting.

### Fixed

- Passkey Settings no longer fails silently on Save when the app's files didn't load in the browser
  (for example a deploy that didn't publish them): the form says so and what to run, and won't turn
  passkeys on until they load; turning them off still saves. The User form no longer shows an
  error then either; its Passkeys section just stays hidden.
- A flagged passkey's card no longer says it was disabled: flagging never disables a passkey.
- An out-of-range number in Passkey Settings names the setting exactly as the form labels it.
- Passkey cards show short provider names (one provider's name was a long description with a web
  link), and Desk and the `/passkeys` page pick up new provider names right after an app update.
- Trusted App Origins help links to the mobile apps guide and shows its whole text.
- Saving an RP ID change now finishes after you confirm "Change the RP ID?"; you no longer click
  Save twice.
- Links in Passkey Settings ("Learn more", links in notices) are underlined so they read as links.
- Change emails: a passkey name containing `<` or `&` shows as typed, a passkey with no name is
  named by its ID, and the added email's IP address sits inside its sentence and is escaped.
- "No Relying Party ID" (the Passkey Settings notice and the Save refusal) says where Passkey RP ID
  is (the Relying Party tab) and, if you just set host_name, to wait a minute and save again.
- A host_name ending in a slash (`https://erp.example.com/`) counts as the site's address:
  passkeys turn on without listing it under Passkey Origins, and emails name it.
- On a phone, a flagged passkey's warning uses the card's full width instead of a narrow column.
- The Trusted App Origins error gives the same iOS advice as the field's help.
- Docs: the login lock is per user and per IP address (not "IP-based"), and passkey sign-in doesn't
  count toward it; the security guide names the real System Settings option to turn off.

### Maintenance

- Weekly grouped update PRs for GitHub Actions, pre-commit and Python, only for releases at least 7
  days old.
- Bug report and feature request forms; security reports go to the private form.
- pre-commit now checks the YAML under `.github/`.
- CodeQL code scanning for Python and JavaScript on every push and pull request.
- A server test keeps the reference docs in step with the code: every Passkey Settings field needs a
  row in the configuration guide (the five mobile-app fields now have one), and every error type a
  client can receive needs an entry in the REST API reference.
- A translation template (`passkeys/locale/main.pot`) for the server-side strings, so translators
  can start.

## [15.0.8] / [16.0.8] — 2026-11-16

### Upgrade notes

- Optional: add the one-time reverse-proxy rule for `/.well-known/passkey-endpoints` if you want
  password managers to find the passkey page (`docs/install.md`).
- Custom UIs that read `credentialViewModel(cred).badge` must handle `null` (see Changed).
- Nothing to do for the settings form: the Mobile Apps fields moved into a folded section on the
  Relying Party tab, and one notification setting was renamed by what it does (see Changed).

### Added

- `/.well-known/passkey-endpoints` (W3C Passkey Endpoints, a Working Draft): while a passkey login
  mode is on, password managers can send users straight to `/passkeys` to add or manage a passkey.
  The URLs come from pinned configuration. It needs a one-time reverse-proxy rule on the RP ID host
  (`docs/install.md`).
- Passkey Settings keeps a history: each change shows in the form's timeline with who made it,
  when, and the old and new value.

### Changed

- Passkey cards (the `/passkeys` page and Desk) say "Synced" for a backed-up passkey and "This
  device only" for one that cannot be backed up; a passkey that could sync but has not yet shows
  neither, instead of the old "Device-bound".
- For custom UIs: `credentialViewModel(cred).badge` is now `null` when neither label applies, so
  check it before reading `badge.key` or `badge.synced`. If you list credentials yourself, also
  select `backup_eligible` (`docs/custom-ui.md`).
- Passkey Settings shows a setting only when it can apply: OTP fallback with Passkey as Second
  Factor, the first passkey after an email-link or social sign-in with Login with Passkey, and the
  Mobile Apps fields as a folded section on the Relying Party tab that opens once one is set.
  "Notify on Password Login by Passkey Holder" is now "Log password sign-ins by passkey holders"
  (it records a risk event and emails no one), and warnings name each setting as the form labels it.
- Passkey cards name 46 more providers and security keys: the provider list is refreshed to
  upstream's 2026-11-15 version, and release builds now fail when it falls more than 30 days behind.

### Security

- Passwordless passkey sign-in is limited per IP address and no longer follows core's
  wrong-password lockout: wrong passwords can't lock a user out of passwordless passkey sign-in,
  and a passkey sign-in no longer resets the count a password guesser is held to. The password
  steps keep core's lock: the second factor, and the one-time password check that sets up a
  passkey enrolled without user verification for passwordless use.

### Fixed

- On Frappe v15 and v16, disabling or deleting another user no longer ends the acting
  administrator's own re-authentication (sudo) window, so their next passkey change does not ask
  them to confirm again. Signing out still ends it.

### Documentation

- Revoking, disabling or deleting a passkey does not end the user's existing sessions; operations
  and recovery docs give the Desk step (and the console line) that signs the user out everywhere.
- Synced passkeys are AAL2-class under NIST SP 800-63B-4 and the app does not restrict credential
  type; a passkey sign-in proves identity only, and roles still come from the User record, also on
  LDAP and social-login sites.

### Tests

- Regressions for bug classes other passkey implementations hit: a disabled credential cannot sign
  in, finish a second factor or confirm an action; each ceremony state is consumed only by its own
  ceremony type; a completed second-factor state or uv-setup record cannot be replayed; and each
  guest ceremony endpoint is limited per IP address.
- One passkey assertion cannot serve as both factors of a sign-in: the second factor takes only
  the state of its own flow's password check, and a passwordless sign-in never takes a second-factor
  step. The well-known documents are pinned as guest `GET` endpoints.

## [15.0.7] / [16.0.7] — 2026-10-23

### Added

- Stale-passkey cards and enrollment guidance, a visible/filterable credential RP ID, and a
  System Manager Desk alert for RP/address mismatches and unavailable passkey paths.
- RP-change impact counts and guarded bulk removal of stale, unflagged credentials in settings.
  The APIs expose the operational site RP and each credential's stale/usable status.

### Changed

- Login, confirmation, enrollment counts and last-passkey guards use enabled credentials made for
  the operational site RP. Stale-only users return to password/core OTP where allowed; the OAuth
  password grant follows the same rule. Site-wide password disable remains enforced.
- RP changes retain credential rows: reverting the RP and origins restores retained enabled
  passkeys. A surviving mobile-app path keeps passkey requirements active even without web access.

### Security

- Refuse OAuth password-grant bearer-token insertion for users with a usable passkey and
  passkey-only or passkey-second-factor requirements, and sites with password login disabled. This
  closes the bypass on older supported Frappe versions whose OAuth password validator skips the final login veto.

### Fixed

- RP/address mismatches with no operational path no longer trap users behind unusable passkey
  requirements or write an Error Log on each login-page view. Existing stale credentials are
  refused distinctly from unknown credentials, so browsers are not told to forget them.
- Ceremonies re-check the RP before creating a credential, session or confirmation grant;
  second-factor RP changes do not re-arm. Signals use the response RP and only its usable keys,
  and are suppressed when no operational RP exists.
- The login and portal page scripts no longer leak onto other pages served by the same worker.
  They were appended to Frappe's cached page-asset lists in place; on a signed-in page the leaked
  login script could clear the session cookie.
- Guest endpoints share an IPv6 /64 rate limit, preventing address rotation within that subnet
  from bypassing the app limit while retaining full IPs in audit records.
- Email identifiers are trimmed and lowercased before password authentication; username aliases
  and `Administrator` retain their case.
- Passkey Settings rejects negative or excessive integer values, including re-authentication
  windows longer than one hour.

### Tests

- Added correct-password regressions for the core login API, `cmd=login`, and OAuth
  password-grant token insertion. These must pass on every supported Frappe revision.

## [15.0.6] / [16.0.6] — 2026-10-20

### Fixed

- Saving Passkey Settings no longer fails when the job queue is full; Recalculate reports when
  the enforcement preview recount cannot start.
- Deleting a WebAuthn User Handle now requires removing the user's passkeys first, including
  disabled passkeys, so existing passkeys cannot lose their passwordless login identity.
- System Manager desk loads no longer scan every user. The settings enforcement preview is
  counted in the background (after a save, daily, or on **Recalculate**) and cached for the saved
  policy with the time counting started; the open form picks up the new count. A recount that
  started earlier never replaces a newer one.
- Sites set up before 15.0.0 could not save Passkey Settings: the old "All Users" scope value is no
  longer an option, so "Require a passkey from" showed blank. A patch maps the old enrollment
  policy to the new settings, clears the System Manager enforcement flag for non-enforcing
  policies, and carries over exemptions from the old Passkey Enforcement Exempt role.
- Changing or clearing the RP ID asks for confirmation once, when you leave the field or save, instead of on
  every keystroke.

### Added

- The app's logo and colour show in Frappe's About dialog (v16+). Passkeys does not add a tile to
  the apps screen.

### Changed

- Verified against current Frappe develop: its hashed session ids, the new Activity Log store and
  the Frappe fix that ignores a client-sent `validate_rename`.
- The README, `docs/install.md` and `SECURITY.md` now state what CI runs on every release line and
  what the daily upstream run checks, in place of general advice to validate on staging. Rollout
  steps stay in `docs/operations.md`. Vulnerability reports go straight to GitHub's private
  reporting form; the public-issue fallback is gone.

## [15.0.5] / [16.0.5] — 2026-09-30

### Security

- An impersonated session is now read-only for passkeys. Renaming or removing a passkey, the
  passkey-only switch, confirmations, password re-auth, `@passkey_protected` actions, the
  enrollment nudge and enforcement events, and the per-user exemption and grace reset all refuse
  it, as registration already did, with a new typed error, `ImpersonatedSessionRefused` (403, a
  `PermissionError`; registration used to raise a plain `PermissionError`), which the client maps
  to `impersonated_session`. An impersonated write no longer spends the user's nudge prompts, grace
  logins or rate limits, and a known or reset password can no longer open a management window from
  that session.
- The passkey DocTypes (WebAuthn Credential, WebAuthn User Handle, Passkey Settings and its
  enforcement roles) refuse an impersonated session in their controllers, with the same error, on
  insert, save, delete (the Passkey Settings Single included), rename (`validate_rename=false`
  included) and v16 discard, whoever is impersonated, the Administrator included. The lock prevents
  accidental or hidden changes while impersonating; it is not a boundary against a determined
  administrator. `docs/security.md` lists what it leaves out by design: a normal sign-in with a
  known or reset password or an API key, background bulk jobs, comments, tags, shares and other
  metadata on passkey records, and User deletes and renames.

### Changed

- The boot payload carries `impersonated`. The Desk and portal show an impersonated user's
  passkeys read-only, with no enrollment nudge or enforcement gate, and the User form hides its
  enforcement recovery buttons and credential-list link.
- A confirmation the server refuses to start now shows the server's reason
  (`confirmation_failed`) instead of "Couldn't reach the confirmation service".
- Each release line's `pyproject.toml` declares only its own Frappe range, as the Frappe Cloud
  Marketplace requires: `>=15.108.0,<16.0.0` on `version-15` and `>=16.18.3,<17.0.0` on
  `version-16`. `develop` keeps `>=15.108.0,<18.0.0`.

## [15.0.4] / [16.0.4] — 2026-09-29

### Fixed

- Enabling a login mode on a site without an `encryption_key` no longer fails: like Frappe core,
  the app now creates and saves the key on first need. An empty key entry is still refused, and
  credential exports still require the original key.

### Changed

- The app's contact email is hello@andrometiq.com.
- Passkey Settings: "Allow First Enrollment on Weak Login" is now "Allow First Passkey After
  Email-Link or Social Sign-in", with help text that lists the sign-ins it covers; the
  Re-authentication Window help text no longer says "sudo gate".
- The setting's field is renamed from `passkey_allow_first_enrollment_on_weak_login` to
  `passkey_allow_first_enrollment_on_external_login`; a patch carries each site's value over on
  migrate. Code that reads the old field name must switch to the new one. The matching risk event
  is now `passkeys:external_login_enrollment` (was `passkeys:weak_login_enrollment`). A user
  signed in by email link or social login within the ten minutes before the upgrade may need to
  sign in again to add a first passkey.

## [15.0.3] / [16.0.3] — 2026-09-27

### Changed

- The "Why passkeys are safer" explainer's final address is
  https://andrometiq.com/software/passkey/why-passkeys-are-safer/; the security-posture panel, the
  README and the docs link there, and the old GitHub Pages address redirects to it.

## [15.0.2] / [16.0.2] — 2026-09-26

### Changed

- The dependency probe documents why its fixed child-process import is safe, with a rule-specific
  suppression for the Frappe Cloud Marketplace security scan; no behaviour change.
- The "Why passkeys are safer" link in the security-posture panel points to the product page,
  https://andrometiq.com/software/passkey/, and the old GitHub Pages address redirects there.

## [15.0.1] / [16.0.1] — 2026-09-26

### Fixed

- OTP fallback now completes on the stock login page: its single-use marker survives core's
  site-cache clear when the OTP submission omits `usr`.
- Expired action confirmations show the timeout message instead of a passkey verification failure.
- Last-passkey refusals name the setting that blocks removal or disabling (the per-user Passkey
  Only Login flag or site-wide Disable Username/Password Login) and the fix that satisfies it.
- Protected app actions use action-neutral browser-session and confirmation prompts; management
  gates keep their management wording.

### Documentation

- Custom UI, REST, security, operations, recovery, configuration and mobile-app docs filled in
  where a docs-only integration hit gaps: CSRF on authenticated `www` pages, the stock enrollment
  gate on custom pages, the autofill `uv_setup_required` branch, helper return shapes, the
  passkey-only floors, System Manager read paths, and a GET-based association-file check.

## [15.0.0] / [16.0.0] — 2026-09-24 — First public release

### Added

- Passwordless sign-in with discoverable passkeys: username-field autofill (conditional UI), a
  "Sign in with a passkey" button, and cross-device sign-in by QR code.
- Passkey as a second factor after the password, in Frappe's own two-factor flow, with an optional
  one-time-code fallback.
- `@passkey_protected` for any whitelisted method: a single-use confirmation grant bound to the
  user, session, action and the arguments listed in `bind_params`. A passkey is required unless an
  action opts in with `allow_password_fallback=True`. `allow_sudo_window=True` (off by default) lets
  a live management sudo window satisfy the gate with no new gesture. Dialogs show an explicit action
  label and only the parameters declared safe to display.
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

- `cbor2`, which the app uses directly to decode public keys, is declared with a patched floor
  (`>=5.9.0`) instead of arriving only through `webauthn`.
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
  signed-in browser session; API-key (`token` or `Basic`) or OAuth bearer requests get
  `BrowserSessionRequired` (403) and never
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

[Unreleased]: https://github.com/Andrometiq/frappe-passkeys/compare/v16.0.8...develop
[15.0.8]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.8
[16.0.8]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.8
[15.0.7]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.7
[16.0.7]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.7
[15.0.6]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.6
[16.0.6]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.6
[15.0.5]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.5
[16.0.5]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.5
[15.0.4]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.4
[16.0.4]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.4
[15.0.3]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.3
[16.0.3]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.3
[15.0.2]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.2
[16.0.2]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.2
[15.0.1]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.1
[16.0.1]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.1
[15.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v15.0.0
[16.0.0]: https://github.com/Andrometiq/frappe-passkeys/releases/tag/v16.0.0
