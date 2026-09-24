# Operations — day-two playbooks

Running a site with passkeys enabled. For first install see
[`install.md`](install.md); for getting a locked-out user or admin back in see
[`recovery.md`](recovery.md).

## What is durable vs ephemeral

This matters for every backup, restore, and deploy.

**Durable — in the site database, travels with a backup:**

- `WebAuthn Credential` rows — the credential public keys, sign counters, backup
  flags, labels, and metadata. These are the authoritative record. No server
  secret is stored; a public key is useless to an attacker who steals a backup.
- `WebAuthn User Handle` rows — the opaque 64-byte user handles and the per-user
  *Passkey Only Login* flag.
- `Passkey Settings` — every knob.
- Per-user enrollment-nudge state, enforcement grace counters and incapable-device
  notification markers (default-value rows under the `__passkeys` parent). User renames
  carry these values forward; merges retain each existing target value and otherwise
  carry the source value. The old keys are removed. Merging two users who both have a
  WebAuthn User Handle is refused: delete the source user's passkeys and handle first.

**Ephemeral — in Redis, TTL-expiring, deliberately not durable:**

- In-flight login / registration / confirmation ceremonies and their challenges.
- The uv-setup step-up state.
- Action-confirmation grants and the "sudo" re-auth windows.
- The guest browser-binder cookie value hashes and the per-user
  password-failure throttle counters.

A Redis flush (or a deploy that clears the cache) cancels only in-flight
ceremonies: the worst case is a user retrying one sign-in. Nothing enrolled is
lost. Sudo windows and grants simply have to be re-earned.

## Before you enable passkeys on a production site

Release CI tests the app against pinned Frappe baselines; it does not test your deployment.
Before enabling passkeys on a site people depend on:

1. Take a database and private-files backup and confirm it restores. Keep a separate copy of the
   site's `encryption_key`: enabling a mode and verifying a credential export both need it.
2. Try the release on a staging copy behind the same TLS, reverse proxy, and host name as
   production, with the RP ID and Passkey Origins you will use.
3. Make sure an administrator can run the console recovery in [`recovery.md`](recovery.md)
   without relying on the login path you are changing.
4. Enable it for a small group first, with password login still on, and watch the
   [risk events](#monitoring-the-risk-events), enrollment failures, and support requests.
5. Turn on Enforce, passkey-only accounts, or OTP-fallback-off only after that period and a
   recovery drill have gone well.

To back out a rollout, turn both modes off in Passkey Settings — the reversible pause described in
[Disable vs uninstall](install.md#disable-vs-uninstall). That is a site decision, not a way to
unlock one user; lockouts go through [`recovery.md`](recovery.md).

## Changing the RP ID or moving domains

**Changing the Relying Party ID invalidates every enrolled passkey.** It is a
one-way door. Plan a fleet-wide re-enrollment before you do it. Administrator's password is a
break-glass path only while site-wide password login remains enabled and Administrator is not an
enrolled passkey-second-factor user; rehearse console recovery before the cutover.

- **Real domain migration** (the site's public host changes): update `host_name`
  in site config (and Passkey RP ID / Passkey Origins if set explicitly) to the new host, and
  check that the resolved origins are exactly the non-empty set you will serve.
  If the RP ID changes, existing passkeys cannot authenticate under the new RP ID;
  have users re-enroll. Moving to another trusted origin within the same RP ID does
  not itself require new passkeys. The Passkey Settings change dialog warns about
  changing the RP ID.

- **Staging clone / restore to a different host:** inspect **Passkey Settings →
  Relying Party** as a System Manager. Repair the intended host, RP ID and exact
  trusted origins; a mismatch fails closed. Follow
  [Passkeys fail after a restore or host change](recovery.md#passkeys-fail-after-a-restore-or-host-change).
  Recover one manager first if necessary, then affected users individually. Do not
  routinely switch off both login modes or clear every user's passkey-only flag.

- **Stale restore:** credentials that were deleted *after* the backup was taken
  come back when you restore it — the row returns and the authenticator still
  holds the key, so a credential a user had revoked silently works again. After
  any restore, review each user's credential inventory.

## Credential and counter incident response

- **Sign-count regression (possible clone).** When an assertion presents a
  signature counter lower than the stored value, the credential is flagged
  (`flagged=1`, reason `sign_count_regression`) and its owner is emailed on the
  first flag only. The sign-in still succeeds unless *Hard-fail on Sign Count
  Regression* is on. A counter that is equal and non-zero (an exact replay) is
  always rejected. To respond: have the owner review recent sign-ins and delete
  the credential if they don't recognize it.

- **Impossible backup state.** If an authenticator's backup-eligibility flag ever
  changes from what was recorded at registration, or presents backed-up without
  being backup-eligible, the ceremony is refused outright. This needs no operator
  action — it fails closed.

- **Revocation.** Users revoke their own passkeys from the management surface
  (the Desk User form or the `/passkeys` portal page). A delete requires a live
  sudo window (a fresh confirmation or password
  re-auth) and refuses to remove a user's last passkey when that would lock them
  out. System Managers can revoke any user's credential from the WebAuthn
  Credential DocType — **prefer disabling (set `enabled=0`) over deleting** so the
  row survives for forensics. With **Notify on Passkey Changes** on, the owner is
  emailed. The app refuses to remove or disable the last enabled credential while
  **Passkey Only Login** or site-wide password disable is set. Follow
  [account recovery](recovery.md#a-user-lost-their-passkey) for the correct order; the
  site-wide case requires its own recovery path.

## Monitoring the risk events

Security-relevant events are recorded as **Activity Log** rows and structured log
lines.

Activity Log rows (filter on the `content` field, which is `passkeys:<event>`):

| Event | Meaning |
|---|---|
| `passkeys:passkey_added` / `passkey_removed` / `passkey_disabled` | A credential was added, removed, or admin-disabled. |
| `passkeys:passkey_flagged` | A sign-count regression / anomaly was recorded on a sign-in. |
| `passkeys:fallback_used` | A passkey holder completed the second factor with a one-time code instead. |
| `passkeys:weak_login_enrollment` | The restricted first-enrollment-on-weak-login path was used. |
| `passkeys:password_login_by_passkey_holder` | A user who holds an enabled passkey signed in with their password instead. Recorded only when `passkey_notify_password_login` is on (default off). |
| `passkeys:enforce_incapable_device` | A user in scope for enrollment enforcement reported their device cannot create a passkey (the block-and-notify-admin path); always recorded, even when the admin email is deduped. |

Structured error/log entries worth alerting on:

- `passkeys: request host … not in configured origins` — a request reached the
  site on a host outside the configured origins (proxy misconfig, domain move,
  or a clone). Diagnose with the host-change playbook above.
- Grant issued / consumed lines (logger `passkeys`) — the audit trail for the
  action-confirmation primitive.

For enrolled second-factor users, alternate/core login completions are expected to fail unless this
app completed the passkey or its `fallback_to_otp` flow issued the one-time marker consumed after
core OTP succeeds. A direct core OTP completion without that marker is not a supported bypass. A
password rotation between the password and passkey legs also fails by design because the ceremony's
keyed, non-reversible password-hash version no longer matches.

## The self-hoster password-disable override (advanced, at your own risk)

**Goal:** a site that wants *passwords fully disabled site-wide* with passkeys as
the only first factor, on v15 / v16, before Frappe core natively supports it.

**Why it isn't already possible on released branches.** Two separate things:

1. Core refuses to *turn on* `disable_user_pass_login` unless at least one of
   Social Login, LDAP, or Login With Email Link is enabled
   (`validate_user_pass_login`). Passkeys are not yet in that allowlist on
   v15 / v16.
2. Even if it were on, `disable_user_pass_login` is enforced at login by throwing
   for **any** username/password login — including Administrator (core's login
   path has no Administrator exemption for this flag, unlike the per-user
   passkey-only veto).

Because of (1), the released-branch levers for "no passwords" are the **per-user
`passkey_only_login` flag** (documented in [`configuration.md`](configuration.md))
or simply leaving email-link on — not the site-wide switch.

**The override**, for operators who accept the risk, is a local patch to core's
`validate_user_pass_login` so it counts an enabled passkey login mode as a
surviving method, letting you turn `disable_user_pass_login` on. Passkey login
does not go through core's `login()`, so it keeps working with the flag on;
password first-factor login is then refused site-wide. Email-link and social login do not
go through that check, so they stay open for any user who is neither Passkey Only nor enrolled
with passkey as a second factor; turn them off separately (System Settings for email-link, the
Social Login Key records for social login) if passwords are meant to be the only thing removed.

**When it is safe:**

- Every user who must retain access — **including Administrator** — has at least
  one enrolled, working passkey, verified *before* you flip the switch.
- You keep tested operator access outside the login path, and have rehearsed
  [recovery of one manager](recovery.md#no-system-manager-can-sign-in).

**When it is a foot-gun:**

- Flipping `disable_user_pass_login` on while Administrator has no working passkey
  locks the site's owner out of the password door too — this flag, unlike the
  per-user passkey-only rule, does **not** exempt Administrator.
- It is a local core patch: it is reverted by any Frappe upgrade, and it is
  outside the app's mergeability guarantees. Re-apply and re-test after every
  update.

**Recovery:** use [the recovery guide](recovery.md#password-login-is-disabled-site-wide).
Recover one account first. Reopening password sign-in site-wide is a last resort,
at your own risk: for that window the whole site is not protected by the password-disable
control. Verify the requester's identity out of band and rule out a planned attack,
including social engineering an admin into lowering defences. The guide keeps the
console change and its restoration steps together.

The upstream plan replaces the local validator override by adding passkeys to
core's `validate_user_pass_login` allowlist, so a local patch would no longer be needed.

## Console authority (stated once)

Raw database writes from an operator console bypass DocType validation and document
hooks, including credential-count and settings guards. Document saves still run their
controllers. Use that authority to restore one trusted manager when nobody can reach
Desk; see [console access](recovery.md#console-access). Site-wide protection changes
are reserved for the guide's last resort.

**Administrator break-glass boundary:** Administrator is exempt from the per-user passkey-only
login veto only. If Administrator explicitly enrolls an enabled credential while Passkey as Second
Factor is active, alternate/core login paths require the app's passkey or one-time OTP fallback like
any other enrolled user. The site-wide `disable_user_pass_login` flag also has no Administrator
exemption. Keep tested console access outside the login path; do not treat an Administrator password
as an unconditional recovery guarantee.
