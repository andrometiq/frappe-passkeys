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
- Per-user enrollment-nudge counters (stored as default-value rows under the
  `__passkeys` parent).

**Ephemeral — in Redis, TTL-expiring, deliberately not durable:**

- In-flight login / registration / confirmation ceremonies and their challenges.
- The uv-setup step-up state.
- Action-confirmation grants and the "sudo" re-auth windows.
- The guest browser-binder cookie value hashes and the per-user
  password-failure throttle counters.

A Redis flush (or a deploy that clears the cache) cancels only in-flight
ceremonies: the worst case is a user retrying one sign-in. Nothing enrolled is
lost. Sudo windows and grants simply have to be re-earned.

## Changing the RP ID or moving domains

**Changing the Relying Party ID invalidates every enrolled passkey.** It is a
one-way door. Plan a fleet-wide re-enrollment before you do it. Administrator's password is a
break-glass path only while site-wide password login remains enabled and Administrator is not an
enrolled passkey-second-factor user; rehearse console recovery before the cutover.

- **Real domain migration** (the site's public host changes): update `host_name`
  in site config and review Passkey RP ID / Passkey Origins. The RP ID does not imply
  `https://<rp_id>`; ensure the compatible `host_name` plus explicit origins resolve to the exact,
  non-empty set you will serve. Move
  new host, accept that all existing passkeys are now invalid, and have users
  re-enroll. The Passkey Settings change dialog restates the consequence.

- **Staging clone / restore to a different host:** Passkey Settings travel with
  the database, so on the clone every login ceremony correctly **fails closed**
  on the host mismatch (it logs `passkeys: request host … not in configured
  origins` and shows the red mismatch banner in Passkey Settings). Passkey-only
  users cannot get into the clone at all (Administrator can, by design). The
  standard post-restore step on a clone is to zero the login modes and clear the
  passkey-only flags — one `bench console` block:

  ```python
  bench --site <clone-site> console
  >>> frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
  >>> frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
  >>> for name in frappe.get_all("WebAuthn User Handle",
  ...         filters={"passkey_only_login": 1}, pluck="name"):
  ...     frappe.db.set_value("WebAuthn User Handle", name, "passkey_only_login", 0)
  >>> frappe.db.commit()
  ```

  (Raw DB writes bypass the settings guards on purpose — this is site-admin
  authority; see "Console authority" below.)

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
  row survives for forensics. Either way the owner is emailed, and the app refuses
  to remove/disable the last enabled credential of a passkey-only user (or under
  site-wide password disable) until the flag is cleared.

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

Structured error/log entries worth alerting on:

- `passkeys: request host … not in configured origins` — a request reached the
  site on a host outside the configured origins (proxy misconfig, domain move,
  or a clone). Diagnose with the host-change playbook above.
- `passkeys: 2FA floor desync` — logged once per day when
  `passkey_as_second_factor` is on but core Two Factor Authentication has been
  turned off out-of-band. The final login veto still blocks enrolled users, but
  the required defence-in-depth backstop is gone; re-enable Two Factor
  Authentication or turn off "Passkey as Second Factor".
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
password, email-link, and social first-factor logins are then all refused
site-wide.

**When it is safe:**

- Every user who must retain access — **including Administrator** — has at least
  one enrolled, working passkey, verified *before* you flip the switch.
- You keep a tested `bench console` path to flip the flag back off (below), off
  the network path that the flag closes.

**When it is a foot-gun:**

- Flipping `disable_user_pass_login` on while Administrator has no working passkey
  locks the site's owner out of the password door too — this flag, unlike the
  per-user passkey-only rule, does **not** exempt Administrator.
- It is a local core patch: it is reverted by any Frappe upgrade, and it is
  outside the app's mergeability guarantees. Re-apply and re-test after every
  update.

**The recovery / kill-switch** (also see [`recovery.md`](recovery.md)):

```python
bench --site <site> console
>>> frappe.db.set_single_value("System Settings", "disable_user_pass_login", 0)
>>> frappe.db.commit()
>>> frappe.clear_cache()
```

This is the durably-correct approach the upstream plan replaces: the core merge
adds passkeys to the `validate_user_pass_login` allowlist so no patch is needed.

## Console authority (stated once)

`bench console`, System Console, and raw `db_set` writes bypass **every**
validation guard in this app — the credential-count floor, the disable guard, and
the two-factor floor guard. That is intentional: console access is site-admin
authority, out of the threat model. It is also what makes every lockout in
[`recovery.md`](recovery.md) survivable.

**Administrator break-glass boundary:** Administrator is exempt from the per-user passkey-only
login veto only. If Administrator explicitly enrolls an enabled credential while Passkey as Second
Factor is active, alternate/core login paths require the app's passkey or one-time OTP fallback like
any other enrolled user. The site-wide `disable_user_pass_login` flag also has no Administrator
exemption. Keep tested console access outside the login path; do not treat an Administrator password
as an unconditional recovery guarantee.
