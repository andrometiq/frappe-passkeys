# Recovery — getting locked-out users and admins back in

Written to be followed at 2am. Every command here runs in `bench console`
(`bench --site <site> console`) and uses raw database writes on purpose — those
bypass the app's validation guards, which is exactly what you need when a guard
is what is standing between you and access. Always finish a console block with
`frappe.db.commit()`.

**Administrator is a limited break-glass path:** Administrator is exempt from the per-user
passkey-only login rule. Administrator is not exempt from site-wide `disable_user_pass_login`, and
an Administrator who explicitly enrolled an enabled credential while Passkey as Second Factor is
active is protected like any other enrolled user. Try Administrator when those conditions do not
apply; otherwise use the console path from the start.

---

## Scenario A — a user set "Passkey Only Login" and lost all their passkeys

Symptom: the user cannot log in with their password (or email link, or social);
they get "This account signs in with a passkey."

Fix: a System Manager clears the flag. Either open **WebAuthn User Handle** in
Desk, find the user's row, untick *Passkey Only Login*, and save — or:

```python
bench --site <site> console
>>> name = frappe.db.get_value("WebAuthn User Handle", {"user": "user@example.com"})
>>> frappe.db.set_value("WebAuthn User Handle", name, "passkey_only_login", 0)
>>> frappe.db.commit()
```

The user can now log in with their password and re-enroll a passkey. (The Desk
save path also enforces a "needs ≥1 enabled credential" floor when *setting* the
flag; clearing it is always allowed. The console write skips that floor entirely.)

---

## Scenario B — a passkey-only user whose account still has a password, no passkeys left

Same as Scenario A. Clearing *Passkey Only Login* restores their password login.
If they have no password set at all (a social-only account), clear the flag and
have them sign in with their social / email-link method, then re-enroll a passkey.

---

## Scenario C — a user lost their passkey second factor and OTP fallback is off

Symptom: the user's password is accepted but the passkey step-up can't be
completed, and *Allow OTP Fallback for Passkey Second Factor* is off, so there is
no code path.

Options, cheapest first:

1. Temporarily turn *Allow OTP Fallback for Passkey Second Factor* **on** in
   Passkey Settings, have the user complete with a one-time code, let them
   re-enroll a passkey, then turn it back off.
2. Or use core's own two-factor recovery for that user (reset their OTP / 2FA per
   your normal Frappe 2FA process), then have them re-enroll.

Core OTP must be entered through this app's `fallback_to_otp` handoff. That flow creates the
short-lived, one-time marker the final login hook requires; sending OTP directly through another
core path does not bypass the enrolled-user passkey requirement.

---

## Scenario D — the site owner is locked out after the password-disable override

Symptom: you turned on site-wide `disable_user_pass_login` (the self-hoster
override in [`operations.md`](operations.md)), and now even Administrator's
password is refused with "Login with username and password is not allowed."

This flag has **no Administrator exemption** — it closes the password door for
everyone. Flip it back off from the console:

```python
bench --site <site> console
>>> frappe.db.set_single_value("System Settings", "disable_user_pass_login", 0)
>>> frappe.db.commit()
>>> frappe.clear_cache()
```

Administrator (and everyone else) can now log in with a password again. Only
re-enable the override once every account that needs it — Administrator
included — has a verified, working passkey.

---

## Scenario E — Two Factor Authentication is jammed on

Symptom: you tried to turn off core *Enable Two Factor Authentication* and got
"Cannot disable Two Factor Authentication…". That guard fires because *Passkey as
Second Factor* is still on.

Fix: turn off **Passkey as Second Factor** in Passkey Settings first, then disable
Two Factor Authentication normally. If the settings page itself is unreachable, do
it from the console:

```python
bench --site <site> console
>>> frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
>>> frappe.db.commit()
```

---

## Scenario F — restore a site to a new host and nobody can log in

Symptom: after restoring a backup onto a different host, every passkey sign-in
fails and Passkey Settings shows a red host-mismatch banner.

This is the fail-closed behaviour, not corruption — the RP ID / origins in the
restored settings don't match the new host. Zero the login modes and clear the
passkey-only flags so people can get in with passwords, then re-enroll or fix the
RP ID deliberately:

```python
bench --site <site> console
>>> frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
>>> frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
>>> for name in frappe.get_all("WebAuthn User Handle",
...         filters={"passkey_only_login": 1}, pluck="name"):
...     frappe.db.set_value("WebAuthn User Handle", name, "passkey_only_login", 0)
>>> frappe.db.commit()
```

See the RP-ID / domain-change playbook in [`operations.md`](operations.md) before
re-enabling — changing the RP ID invalidates every existing passkey.

---

## Last resort — remove the app entirely

If you need passkeys gone and nothing above applies, uninstall the app
(`bench --site <site> uninstall-app passkeys`). Uninstall is guarded against the
two lockout cases above — it refuses while a passkey-only user exists or while
site-wide password login is disabled with no other method — so clear those first
using the scenarios above. Before dropping the tables, uninstall writes a site-bound,
HMAC-SHA256-authenticated version-2 export atomically at mode `0600`; retain its printed path and the
matching site `encryption_key`. Default restore requires empty passkey tables. See
[`install.md`](install.md#credential-export-on-uninstall).
