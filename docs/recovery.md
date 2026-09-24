# Recovery — getting locked-out users and admins back in

Every procedure here assumes a **System Manager** can sign in and fixes the affected
account in Desk. Recover one account at a time. Do not turn a
site-wide protection off to get one person in. Before you change anyone's sign-in,
verify the requester's identity out of band: a lockout story is also how an attacker
talks an admin into lowering the defences.

If no System Manager can sign in, go to
[No System Manager can sign in](#no-system-manager-can-sign-in).

## The Desk actions used below

- **Disable a lost passkey.** Open **WebAuthn Credential**, filter **User** to the
  account, open the lost credential, untick **Enabled**, and save. A disabled
  credential can no longer sign in and no longer counts for the passkey second
  factor or for enforcement. Prefer disabling to deleting: the row stays for
  investigation. The owner is emailed when **Notify on Passkey Changes** is on. The
  form refuses to disable the user's last enabled credential while their **Passkey
  Only Login** is on, or while System Settings → **Disable Username/Password Login**
  is on. Clear the per-user flag first; the site-wide case is
  [its own scenario](#password-login-is-disabled-site-wide).
- **Clear Passkey Only Login.** Open **WebAuthn User Handle**, open the user's row,
  untick **Passkey Only Login**, and save. Clearing is always allowed. The user's own
  switch at `/passkeys` needs a fresh passkey confirmation, so a user who has lost
  every passkey cannot clear it themselves. Clearing it does not create a password;
  the user signs in with whatever other method their account already has.
- **Exempt a user from the enrollment prompt.** Open the user's **User** form →
  **Passkeys** section, and click **Exempt from passkey enforcement**. **Reset grace
  logins** in the same section gives them their **Grace sign-ins** budget again.
  **Remove enforcement exemption** puts them back in scope. These buttons show while
  a passkey is required from someone.

Once the user is back in, they enroll a replacement from **User → Passkeys** or
`/passkeys` and test a fresh sign-in. Turn **Passkey Only Login** back on only after
they hold at least two working passkeys.

---

## A user lost their passkey

This covers passwordless sign-in, **Passkey Only Login**, and a lost passkey second
factor. It applies with **Allow OTP Fallback for Passkey Second Factor** off: leave it
off. Do not turn it on to get one user in.

1. If the user still has another working passkey, they sign in with it. Then disable
   the lost one. Done.
2. Otherwise, if **Passkey Only Login** is on for them, clear it.
3. Disable each lost passkey.
4. The user signs in again:

   | After step 3 | Their next sign-in |
   |---|---|
   | No enabled passkey, **Passkey as Second Factor** on | Password, then core's one-time code if one of their roles requires Two Factor Authentication; otherwise the password alone. |
   | No enabled passkey, **Login with Passkey** only | Their account's other method: password, email link, social login or LDAP. |
   | Any enabled credential left, **Passkey as Second Factor** on | Still asked for a passkey after the password, even if that credential is physically lost. Disable it too. |

5. They enroll a replacement and test it.

Resetting the user's core two-factor setup does not help while an enabled credential
remains: the passkey rule still applies.

If the site's **Maximum Passkeys per User** blocks the replacement, delete obsolete
disabled rows for that user after noting what you need for the record: disabled rows
still count toward the cap.

## The enrollment prompt blocks a user

Symptom: after sign-in, "Set up a passkey to continue" will not go away. This is a
prompt after login, not a failed sign-in.

1. Help the user enroll on a capable device or with a security key.
2. If they need more time, **Reset grace logins** on their **User → Passkeys**
   section. A budget of zero still gives no deferral.
3. If they cannot enroll, **Exempt from passkey enforcement**. Remove the exemption
   once they have enrolled.

If every System Manager is stuck in the prompt, see
[No System Manager can sign in](#no-system-manager-can-sign-in).

## Password login is disabled site-wide

Symptom: password sign-in returns "Login with username and password is not allowed."
System Settings → **Disable Username/Password Login** is on. This setting has no
Administrator exemption. It does not block **Login with Passkey**, email link, social
login or LDAP.

1. A user with another working passkey signs in with it; disable the lost one.
2. A user who is still signed in somewhere enrolls a replacement first, then you
   disable the lost one.
3. A user with no passkey and no other sign-in method cannot get in while the setting
   is on, and the form refuses to disable their last credential. There is no per-user
   override. Reopening password sign-in is site-wide: see
   [Last resort](#last-resort--at-your-own-risk).

## Passkeys fail after a restore or host change

Symptom: passkey sign-in fails and **Passkey Settings** shows that the resolved RP ID /
origins do not match this site's host. The error log shows
`passkeys: request host … not in configured origins`. The credentials are intact; the
sign-in fails closed on purpose.

1. A System Manager who can sign in with a password opens **Passkey Settings →
   Relying Party**.
2. Set **Passkey RP ID** and **Passkey Origins** so they match the host you serve.
   Leave **Passkey RP ID** blank to use the site's `host_name`. Adding an origin under
   the same RP ID keeps every passkey working. Changing the RP ID makes every existing
   passkey unusable; see [Changing the RP ID](operations.md#changing-the-rp-id-or-moving-domains).
3. Recover anyone still locked out through [A user lost their passkey](#a-user-lost-their-passkey).

A restore can also bring back a credential that was revoked after the backup was
taken. Review restored credentials. Do not switch the login modes off or clear every
user's **Passkey Only Login** as a routine post-restore step.

## Two Factor Authentication will not turn off

Symptom: saving System Settings with **Enable Two Factor Auth** unticked fails with
"Cannot disable Two Factor Authentication…". **Passkey as Second Factor** needs core
two-factor authentication as its backstop, so the save is refused on purpose. This is
a policy change, not a lockout. If you really mean to retire the passkey second
factor, untick **Passkey as Second Factor** in **Passkey Settings** first, then turn
core two-factor authentication off.

---

## No System Manager can sign in

Try these in order. As soon as one System Manager can reach Desk, fix everyone else
with the procedures above.

**1. Sign in as Administrator.** Administrator is exempt from **Passkey Only Login**.
Its password works when both are true:

- System Settings → **Disable Username/Password Login** is off;
- Administrator has no enabled **WebAuthn Credential** while **Passkey as Second
  Factor** is on. An enrolled Administrator completes the passkey step like anyone else.

`bench --site <site> set-admin-password` replaces a forgotten Administrator password;
it does not bypass either condition. With shell access to the bench,
`bench --site <site> browse --user Administrator` opens Desk already signed in as
Administrator. Neither turns Administrator's password off; see
[Hardening Administrator](security.md#hardening-administrator).

**2. Make a trusted user a System Manager.** Pick an existing, enabled user who can
still sign in, and confirm out of band that they should hold the role. In the
[console](#console-access):

```python
frappe.get_doc("User", "user@example.com").add_roles("System Manager")
frappe.db.commit()
```

They sign in as usual and fix the affected accounts in Desk. Remove the role afterwards
if it was only for the recovery. (`bench add-system-manager` creates a *new* user; it
does not grant the role to an existing one.)

**3. Restore one System Manager's own account.** Use this only when nobody who can sign
in should receive the role. It clears that one account's **Passkey Only Login** and
disables its passkeys, so its password sign-in works again. It does nothing while
**Disable Username/Password Login** is on.

```python
user = "user@example.com"
handle = frappe.db.get_value("WebAuthn User Handle", {"user": user})
if handle:
    frappe.db.set_value("WebAuthn User Handle", handle, "passkey_only_login", 0)
for name in frappe.get_all(
    "WebAuthn Credential", filters={"user": user, "enabled": 1}, pluck="name"
):
    frappe.db.set_value("WebAuthn Credential", name, "enabled", 0)
frappe.db.commit()
```

These raw writes skip the owner's change email: tell them through a trusted channel.
They sign in with their password (and core's one-time code if their role requires it)
and enroll a new passkey.

If the enrollment prompt then blocks that manager, exempt just that account:

```python
from passkeys import boot

boot.set_exempt("user@example.com", True)
frappe.db.commit()
```

Remove it from **User → Passkeys** once they have enrolled.

**4.** Only if none of this gives you one working System Manager, go to
[Last resort](#last-resort--at-your-own-risk).

## Console access

From the bench directory:

```bash
bench --site <site> console
```

Run the Python blocks there after replacing the placeholders. Raw `frappe.db` writes
skip the app's form guards, which is why they work when a guard is what locks you out.
Note the original values before you change anything, so you can put them back.

---

## Last resort — at your own risk

Each step here turns a control off for **the whole site**, not for one account. For
that window the site is not protected by it. Be sure the request is genuine and not
part of a planned attack that depends on an admin lowering the defences, and verify
the requester's identity out of band first. Make only the one change you need, get
one System Manager in, and turn the control back on straight away.

**Password sign-in is refused site-wide and no account can be restored another way.**

```python
frappe.db.set_single_value("System Settings", "disable_user_pass_login", 0)
frappe.db.commit()
frappe.clear_cache()
```

This does not clear anyone's **Passkey Only Login** or passkey second factor; restore
one manager with [step 3](#no-system-manager-can-sign-in), then fix the rest in Desk.
Turn it back on (tick **Disable Username/Password Login** in System Settings) only
after everyone who must keep access, Administrator included, has a working passkey.

**The enrollment prompt blocks every System Manager** and exempting one account did not
work:

```bash
bench --site <site> execute passkeys.recovery.disable_enforcement
```

This sets **Require a passkey from** to *No one* and unticks **Always require a passkey
from System Managers**; nothing else changes. Turn them back on in **Passkey Settings →
Enrollment**.

**The passkey second factor itself must come off**, because no account can be restored
another way:

```python
frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
frappe.db.commit()
frappe.clear_cache()
```

Enrolled users lose the passkey step site-wide; core two-factor authentication still
applies. Turn **Passkey as Second Factor** back on in **Passkey Settings** as soon as
one manager is in.

---

## Removing the app

Uninstalling is not a recovery step. If passkeys should be gone for good, recover a
System Manager first, then follow [Uninstall](install.md#uninstall): it lists the
lockout guards and the credential export it writes.
