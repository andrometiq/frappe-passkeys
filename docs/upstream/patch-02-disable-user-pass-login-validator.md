# Patch 02 — passkeys as a surviving login method in `validate_user_pass_login`

**Target:** `frappe/core/doctype/system_settings/system_settings.py`
**Base:** `develop` @ `9b48af62aff88522638e38b1f4738e79ce0902fd`
**PR:** rides Stage 1 or Stage 2 (whichever lands first); the message only makes sense once the
`login_with_passkey` field exists, so functionally it belongs to **Stage 2**.
**Size:** +1 / −1 code line (+1 message string).

## What it does

`disable_user_pass_login` turns off username/password login. Its validator refuses to enable the
flag unless at least one *other* login method is active — otherwise the site locks everyone out.
Today that allowlist is Social Login **or** LDAP **or** email-link only
(`validate_user_pass_login`, `frappe/core/doctype/system_settings/system_settings.py:182-194`):

```python
	def validate_user_pass_login(self):
		if not self.disable_user_pass_login:
			return

		social_login_enabled = frappe.db.exists("Social Login Key", {"enable_social_login": 1})
		ldap_enabled = frappe.db.get_single_value("LDAP Settings", "enabled")

		if not (social_login_enabled or ldap_enabled or self.login_with_email_link):
			frappe.throw(
				_(
					"Please enable atleast one Social Login Key or LDAP or Login With Email Link before disabling username/password based login."
				)
			)
```

Passkey first-factor login runs through `login_as` (not `LoginManager.login()`), so it already
survives `disable_user_pass_login` at runtime (the flag only gates `login()`,
`frappe/auth.py:150-151`). But the **validator** doesn't know that, so a passkey-only site can't
set the flag without also lighting up an unrelated method (email-link) purely as a formality.

## The diff

```diff
-		if not (social_login_enabled or ldap_enabled or self.login_with_email_link):
+		if not (
+			social_login_enabled
+			or ldap_enabled
+			or self.login_with_email_link
+			or self.login_with_passkey
+		):
 			frappe.throw(
 				_(
-					"Please enable atleast one Social Login Key or LDAP or Login With Email Link before disabling username/password based login."
+					"Please enable atleast one Social Login Key or LDAP or Login With Email Link or Passkey login before disabling username/password based login."
 				)
 			)
```

`self.login_with_passkey` is the System Settings `Check` field added by the Stage-2 passkey PR
(the app's `Passkey Settings.login_with_passkey`, fieldname chosen up-front to be the future
core name — see `mapping.md`). This one line is the entire "passwordless-only site" story on the
core side.

## Correctness note

The guard is a floor against *site-wide* lockout, not per-user. The passkey app additionally
enforces a **per-user** floor: it refuses `passkey_only_login=1` for a user with zero enabled
credentials, and the Passkey Settings validator refuses any save that would leave no
passkey-capable login mode enabled while any user is `passkey_only_login=1`
(`passkeys/passkeys/doctype/passkey_settings/…` + `passkeys/api/credentials.py`). Those per-user
guards move into core with Stage 2; this patch is only the site-flag allowlist.

## Branch notes (v15 / v16)

Identical function, identical logic; only line numbers drift: `validate_user_pass_login` at v16
`:175`, v15 `:171` (the `social_login_enabled or ldap_enabled or self.login_with_email_link`
condition at v16 `:182`, v15 `:178`). develop-only PR; noted for completeness.
