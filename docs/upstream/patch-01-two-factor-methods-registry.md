# Patch 01 — `two_factor_methods` registry hook

**Target:** `frappe/twofactor.py`
**Base:** `frappe/frappe` `develop` @ `9b48af62aff88522638e38b1f4738e79ce0902fd`
**PR:** Stage 1 — `feat: pluggable two-factor methods` · closes #4252
**Size:** +~45 / −~4 lines (plus tests)

## What it does

Today `frappe/twofactor.py` hard-wires the 2FA method to `OTP App | SMS | Email`
(`get_verification_method` at `:145-146` reads the `two_factor_method` Select; dispatch in
`get_verification_obj` `:191-205` and verification in `confirm_otp_token` `:149-188`). An app
that wants to add a method (passkey, WebAuthn, a hardware push, …) must monkeypatch the two
functions `frappe/auth.py` imports by name (`frappe/auth.py:18-23`; also re-imported at
`frappe/integrations/doctype/ldap_settings/ldap_settings.py:22`).

This patch adds a resolver and routes 2FA issuance and verification through a `two_factor_methods`
hook — consulted in **two** functions (`authenticate_for_2factor` and `confirm_otp_token`);
`get_verification_obj` stays a pure OTP builder (see the note under diff 2). A provider is a dict
of dotted paths keyed by method name:

```python
# in the registering app's hooks.py
two_factor_methods = {
	"Passkey": {
		"is_configured": "passkeys.passkey.passkey_2fa_is_configured",  # (user) -> bool
		"issue":         "passkeys.passkey.passkey_2fa_issue",          # (user, tmp_id) -> verification_obj (dict)
		"verify":        "passkeys.passkey.passkey_2fa_verify",         # (login_manager, otp, tmp_id) -> bool
	},
}
```

`verification_obj` is the same envelope core already returns for OTP (`{"method": ..., "setup":
..., "prompt"?: ...}` — see `process_2fa_for_sms` `:213-218`) plus whatever extra keys the client
handler for that method needs; it rides `frappe.local.response["verification"]` /
`["tmp_id"]` exactly as OTP does today (`authenticate_for_2factor` `:90-91`), so the wire
protocol and `login.js` dispatch (`:311-323`) are unchanged for a new method.

**`is_configured` — the per-user fallback (this is what consults the third contract key).**
`get_two_factor_method_provider()` resolves a method → provider at the *method* level; the
*per-user* gate is `provider["is_configured"](user)`, consulted at each dispatch site. If the
active method is `Passkey` globally but a given user has **no** passkey registered, issuing a
passkey challenge would hard-fail that user's 2FA with no way back — so when `is_configured` is
`False`, dispatch falls through to the built-in OTP path (which self-bootstraps a secret via
`get_otpsecret_for_`). The app already implements exactly this check —
`passkeys.passkey._enabled_credentials(user)` (`passkey.py:709`) — so `is_configured` maps 1:1 to
`bool(_enabled_credentials(user))`. Without this consult, `is_configured` would be a dead contract
key; with it, the provider interface can express "this user can't use this method," which is the
whole point of the key.

**Additivity guarantee:** when `two_factor_methods` is empty or the active method has no
provider, `get_two_factor_method_provider()` returns `None` and every function falls through to
its existing body **unchanged** — `OTP App`/`SMS`/`Email` behaviour is byte-identical, **with one
disclosed exception** (the `tmp_id`-without-`otp` edge case in `authenticate_for_2factor` — see
**Behavior delta** below). The core `Passkey` option itself is only added to the
`two_factor_method` Select in Stage 2 (or by the app's Property Setter pre-merge).

## The diff

### 1. New resolver (insert after `get_verification_method`, `frappe/twofactor.py:145-146`)

```python
def get_verification_method():
	return frappe.get_system_settings("two_factor_method")


# --- added ---
def get_two_factor_method_provider(method: str | None = None):
	"""Return the app-registered provider for a 2FA `method`, or None for the
	built-in OTP App / SMS / Email methods (which keep their existing code path).

	Apps register a method via the `two_factor_methods` hook, mapping a method
	name to a dict of dotted paths::

	    two_factor_methods = {
	        "<Method>": {
	            "is_configured": "app.mod.fn",  # (user) -> bool
	            "issue":         "app.mod.fn",  # (user, tmp_id) -> verification_obj (dict)
	            "verify":        "app.mod.fn",  # (login_manager, otp, tmp_id) -> bool
	        },
	    }
	"""
	if method is None:
		method = get_verification_method()
	provider = (frappe.get_hooks("two_factor_methods") or {}).get(method)
	if not provider:
		return None
	# hook values are lists (last-wins across apps); resolve dotted paths to callables
	return {
		key: frappe.get_attr(val[-1] if isinstance(val, list | tuple) else val)
		for key, val in provider.items()
	}
```

### 2. `authenticate_for_2factor` (`frappe/twofactor.py:80-91`) — route issuance

```diff
 def authenticate_for_2factor(user):
 	"""Authenticate two factor for enabled user before login."""
-	if frappe.form_dict.get("otp"):
+	# the verification leg re-POSTs tmp_id (+ otp, or a provider's own payload);
+	# never re-issue on it — generalises the OTP-only `otp` guard to any method
+	if frappe.form_dict.get("otp") or frappe.form_dict.get("tmp_id"):
 		return
-	otp_secret = get_otpsecret_for_(user)
-	token = int(pyotp.TOTP(otp_secret).now())
 	tmp_id = frappe.generate_hash(length=8)
-	cache_2fa_data(user, token, otp_secret, tmp_id)
-	verification_obj = get_verification_obj(user, token, otp_secret)
+	provider = get_two_factor_method_provider()
+	if provider and not provider["is_configured"](user):
+		provider = None  # method active globally but this user isn't set up for it →
+		                 # fall through to built-in OTP (which self-bootstraps a secret)
+	if provider:
+		verification_obj = provider["issue"](user, tmp_id)
+	else:
+		otp_secret = get_otpsecret_for_(user)
+		token = int(pyotp.TOTP(otp_secret).now())
+		cache_2fa_data(user, token, otp_secret, tmp_id)
+		verification_obj = get_verification_obj(user, token, otp_secret)
 	# Save data in local
 	frappe.local.response["verification"] = verification_obj
 	frappe.local.response["tmp_id"] = tmp_id
```

> **Behavior delta (disclose in the PR — the one place this patch is *not* byte-identical).**
> The guard generalises from `if frappe.form_dict.get("otp")` to
> `if … or frappe.form_dict.get("tmp_id")`. That changes one stock-OTP edge case: a request
> carrying `tmp_id` **without** `otp`. Today (`frappe/twofactor.py:82-91`) that request does **not**
> early-return — it re-runs `get_otpsecret_for_`, generates a fresh token, `cache_2fa_data`, and
> returns a **new** `verification` + **new** `tmp_id` in the response. After the patch it
> early-returns with no re-issue. This is deliberate — the verification leg re-POSTs `tmp_id` and
> must never mint a second challenge — but it is a real change to stock behaviour and must be
> disclosed rather than filed under "byte-identical." Add a regression test for exactly this leg
> (`tmp_id` present, `otp` absent → no re-issue, original challenge still valid).

> The task brief asks that `get_verification_obj` also dispatch through the registry. It is left
> as a pure OTP builder here and issuance is routed one level up in `authenticate_for_2factor`,
> because `get_verification_obj`'s signature is `(user, token, otp_secret)` — a provider has no
> `token`/`otp_secret`, and `tmp_id` (which the provider needs to key its challenge state) is not
> one of its args. Routing at the caller keeps `get_verification_obj`'s contract intact for its
> other reference. If review prefers the dispatch literally inside `get_verification_obj`, add a
> `tmp_id=None` kwarg and a `provider` branch at its top — both are additive; this file notes the
> choice rather than hiding it.

### 3. `confirm_otp_token` (`frappe/twofactor.py:149-188`) — route verification

The provider branch must sit **above** the existing `if not otp:` early-returns (`:153-158`) —
a passkey verification carries no `otp`, so falling through would let it bypass 2FA:

```diff
 def confirm_otp_token(login_manager, otp=None, tmp_id=None):
 	"""Confirm otp matches."""
 	from frappe.auth import get_login_attempt_tracker

+	provider = get_two_factor_method_provider()
+	if provider and not provider["is_configured"](login_manager.user):
+		provider = None  # symmetric with authenticate_for_2factor's issuance gate:
+		                 # a user who fell through to OTP verifies through the OTP path
+	if provider:
+		if not tmp_id:
+			tmp_id = frappe.form_dict.get("tmp_id")
+		# the provider owns its challenge state, expiry, tracker and login_manager.fail()
+		return bool(provider["verify"](login_manager, otp, tmp_id))
+
 	if not otp:
 		otp = frappe.form_dict.get("otp")
 	if not otp:
 		if two_factor_is_enabled_for_(login_manager.user):
 			return False
 		return True
 	...  # unchanged OTP body
```

## Client side (generic `login.js` branch — small, ships in this PR)

`login.js` currently dispatches `verification.method` through a hardcoded
`if/else if` chain (`frappe/templates/includes/login/login.js:317-322`). Add a final generic
arm so an unknown method is handed to a client handler the registering app attaches — mirroring
`request_otp`'s DOM injection (`login.js:362-379`) and firing on `login_rendered` (`:343`):

```diff
 				if (data.verification.method == 'OTP App') {
 					continue_otp_app(data.verification.setup, data.verification.qrcode);
 				} else if (data.verification.method == 'SMS') {
 					continue_sms(data.verification.setup, data.verification.prompt);
 				} else if (data.verification.method == 'Email') {
 					continue_email(data.verification.setup, data.verification.prompt);
+				} else if (frappe.two_factor_methods
+						&& frappe.two_factor_methods[data.verification.method]) {
+					// app-registered method: hand it the verification envelope + tmp_id
+					frappe.two_factor_methods[data.verification.method](data.verification, data.tmp_id);
 				}
```

## Branch notes (v15 / v16)

- The extension-point functions exist on all three branches with the same signatures:
  `authenticate_for_2factor` (v15 `:82`, v16 `:80`), `get_verification_method` (v15 `:146`),
  `confirm_otp_token` (v15 `:150`, v16 `:149`), `get_verification_obj` (v15 `:192`, v16 `:191`).
  The patch applies structurally identically; only line numbers drift.
- **v15 `twofactor.py` reads zero hooks today** (no `frappe.get_hooks` call anywhere in the
  file). v16/develop already call `frappe.get_hooks("send_token_via_sms")` (v16/develop `:306`),
  proving the pattern is acceptable in this exact module. This is a develop-only PR regardless;
  the branch note matters only for the *app's* pre-merge behaviour (on all three released
  branches the app uses its own dispatch, since core has no registry there).
- The `login.js` `verification.method` chain is identical everywhere (v15 `:272-277`); the
  generic arm applies the same way.

## Why maintainers should want this independent of passkeys

It closes #4252 (FIDO2 second factor, open since 2017) by making the *framework* extensible
rather than adding one more hardcoded branch, and it removes the only reason any auth app has to
monkeypatch `frappe.auth`'s 2FA imports. It is the "framework capability" generalization
reviewers historically push toward (Auto Repeat precedent, #7820) — offered up-front.
