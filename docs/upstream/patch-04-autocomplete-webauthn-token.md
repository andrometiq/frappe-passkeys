# Patch 04 — `autocomplete="username webauthn"` on the login input

**Target:** `frappe/www/login.html`
**Base:** `develop` @ `9b48af62aff88522638e38b1f4738e79ce0902fd`
**PR:** rides Stage 1 or Stage 2 (whichever lands first) · **Size:** one token

## What it does

WebAuthn **conditional UI** (passkey autofill — the OS surfacing a saved passkey directly from
the username field) requires the target input to advertise the `webauthn` autocomplete token
alongside `username`. Core's login email input ships `autocomplete="username"` only
(`frappe/www/login.html:23`), so the browser never offers passkeys in the autofill dropdown; the
app currently JS-patches the attribute at runtime.

## The diff

`frappe/www/login.html:21-23`:

```diff
 			<input type="text" id="login_email" class="form-control"
 				placeholder="{% if login_name_placeholder %}{{ login_name_placeholder  }}{% else %}{{ _('jane@example.com') }}{% endif %}"
-				required autofocus autocomplete="username">
+				required autofocus autocomplete="username webauthn">
```

That is the whole change. The `webauthn` token is inert unless a conditional-UI ceremony is
armed (patch 03's `login_rendered` boot), and it is harmless on browsers that don't support it —
they ignore the unknown token and fall back to plain username autofill.

## Branch notes (v15 / v16)

Same element, same single-token change; only the line differs: the `#login_email` input is at
v16 `login.html:13-15`, v15 `login.html:9-11` (both `autocomplete="username"`). develop-only PR.

## Why it's separate from patch 03

It is genuinely independent (it helps any future conditional-UI feature, not just this button),
it is a one-token change a maintainer can approve on sight, and decoupling it means it can ride
the Stage-1 PR if that lands first — the passkey conditional-UI flow simply has no effect until
the bundle from patch 03 is present.
