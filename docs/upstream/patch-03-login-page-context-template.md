# Patch 03 — native login-page slot + bundle (retires the injection shim)

**Target:** `frappe/www/login.py`, `frappe/www/login.html`,
`frappe/templates/includes/login/login.js`
**Base:** `develop` @ `9b48af62aff88522638e38b1f4738e79ce0902fd`
**PR:** Stage 2 · **Size:** +~40 lines across three files

## What it does

Core's login page has no provider extension slot: the buttons are hardcoded conditional Jinja
blocks and the page JS is Jinja-inlined, so asset hooks can only *replace* the template, not
extend it (seam S4/S5). The app copes with `update_website_context`
(`passkeys/shims/login_page.py::website_context`), which conditionally appends the passkey bundle
to `context.web_include_js` on `/login` and lets the bundle DOM-inject its own button — a shim
that drifts with core markup. This patch makes core render the button and load the bundle
**natively**, so the app's `website_context` shim is deleted on merge.

It mirrors the existing `login_with_email_link` wiring exactly (context flag → conditional button
in `.page-card-actions` → hash-routed `login.js` section), which is the most recent merged
precedent for adding a login method (#19363).

## The diff

### 1. `frappe/www/login.py` — context flag

Next to the email-link flag (`frappe/www/login.py:111`):

```diff
 	context["login_with_email_link"] = frappe.get_system_settings("login_with_email_link")
+
+	context["login_with_passkey"] = cint(frappe.get_system_settings("login_with_passkey"))

 	return context
```

(`cint` is already imported in this module.)

### 2. `frappe/www/login.html` — button slot + bundle include

Add a passkey button inside `.page-card-actions`, next to the email-link button
(`frappe/www/login.html:62-66`):

```diff
 	{% if login_with_email_link %}
 	<a href="#login-with-email-link"
 		class="btn btn-block btn-default btn-sm btn-login-option btn-login-with-email-link">
 		{{ _("Login with Email Link") }}</a>
 	{% endif %}
+	{% if login_with_passkey %}
+	<button type="button"
+		class="btn btn-block btn-sm {{ "btn-primary" if disable_user_pass_login else "btn-default" }} btn-login-option btn-login-with-passkey">
+		{{ _("Sign in with a passkey") }}</button>
+	{% endif %}
```

and pull in the ceremony JS/CSS at the foot of the template (core already ships bundled assets
this way; in-core the bundle is a static file under `frappe/public/js/`, not an app `/assets`
path):

```diff
+{% if login_with_passkey %}
+	{{ include_script("passkey.bundle.js") }}
+	{{ include_style("passkey.bundle.css") }}
+{% endif %}
```

### 3. `frappe/templates/includes/login/login.js` — section + conditional-UI boot + verify branch

- A `#login-with-passkey` hash-routed section handler alongside the email-link section
  (pattern: `login.js` sections; the email-link submit handler is the model).
- Conditional-UI (autofill) boot fired from the existing `login_rendered` trigger
  (`frappe/templates/includes/login/login.js:343`) — this is the documented client-side attach
  point:

```diff
 	$(".form-signup, .form-forgot, .form-login-with-email-link").removeClass("hide");
 	$(document).trigger('login_rendered');
+	// passkey conditional UI (autofill) arms itself here when enabled; the bundle
+	// listens for `login_rendered` and calls navigator.credentials.get({mediation:"conditional"})
```

- The **second-factor** display branch is delivered generically by patch 01's `login.js` change
  (`frappe.two_factor_methods["Passkey"]`), so no `Passkey`-specific `verification.method` arm is
  needed here — the passkey bundle registers its handler on that map.

The button click + the conditional-UI assertion both POST the app's guest endpoints
(`passkey.begin_login` / `passkey.verify_login`) and, on success, receive the **core login
envelope** (`{"message": "Logged In", "home_page": ...}`) so `login.login_handlers`
(`login.js:271-333`) does the redirect with zero protocol change.

## Branch notes — the two markup generations (v15/v16 vs develop)

The research errata flags "two markup generations": the JS response envelope
(`data.message` / `verification.method` / `tmp_id`) is **identical on all three branches**, but
the DOM anchors differ, so the app's pre-merge injection shim needs two placement targets and
this native patch lands at different line numbers per branch:

| Anchor | develop | version-16 | version-15 |
|---|---|---|---|
| `#login_email` input (`autocomplete` — patch 04) | `login.html:21-23` | `login.html:13-15` | `login.html:9-11` |
| `.page-card-actions` (button slot) | `login.html:54` | `login.html:45` | `login.html:41` |
| `.social-logins` block | `login.html:69` | `login.html:92` | `login.html:87` |
| `verification.method` dispatch chain | `login.js:317-322` | (same shape) | `login.js:272-277` |
| `login_rendered` trigger | `login.js:343` | (same shape) | (same shape) |
| `context["login_with_email_link"]` (flag sibling) | `login.py:111` | `login.py` | `login.py:114` |

develop's redesign moved the primary form/actions rendering into `email_login_body()` but keeps
the same `.page-card-actions` / `.social-logins` slot names, so the patch shape is the same; only
the surrounding Jinja differs. **This patch targets develop only** (core PR); the table is the
map the app's `shims/login_page.py` uses to stay correct on released branches until the shim is
deleted at merge.
