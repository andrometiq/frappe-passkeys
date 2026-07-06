app_name = "passkeys"
app_title = "Passkeys"
app_publisher = "Frappe Passkeys Contributors"
app_description = "Passkey (WebAuthn) authentication for Frappe"
app_email = "passkeys@example.com"
app_license = "MIT"

# Desk / portal assets — action-confirmation ("passkey signing") client (§7.3)
# ---------------------------------------------------------------------------
# The confirm.* surface is delivered on EVERY desk page independent of login
# modes (§3.0 matrix / A39): consuming apps' @passkey_protected actions must not
# silently break when an admin toggles login modes — it is re-auth, not login.
# passkey_common.js MUST load first (sets the frappe.passkeys_common global the
# confirm bundle reads). Both files are UMD-lite browser globals (no build step);
# they self-gate on `frappe.passkeys` availability at runtime.
#
# Desk management surfaces (§8.1/§8.2/§8.4 — P6 frontend). Order is load-bearing:
# passkey_manage_common.js sets `frappe.passkeys_manage_common` and passkey_confirm.js
# sets `frappe.passkeys.call`/`.confirm`; passkey_desk.bundle.js reads BOTH, so both
# must load before it (frontend manifest §2.1). The desk bundle self-gates on
# `frappe.boot.passkeys.enabled` — a both-modes-off / dormant site removes itself.
app_include_js = [
	"/assets/passkeys/js/passkey_common.js",
	"/assets/passkeys/js/passkey_manage_common.js",
	"/assets/passkeys/js/passkey_confirm.js",
	"/assets/passkeys/js/passkey_desk.bundle.js",
]
app_include_css = [
	"/assets/passkeys/css/passkey_confirm.css",
	"/assets/passkeys/css/passkey_manage.css",
]

# DocType client scripts (§8.1 / §9.4 — P6 frontend)
# --------------------------------------------------
# User form: the "Passkeys" section (own form ⇒ interactive cards + add; another
# user's form, System Manager ⇒ read-only inventory + WebAuthn Credential link,
# §8.6). Passkey Settings form: the §9.4 cross-flag banner matrix + the RP-ID
# one-way-door confirm. Both delegate rendering to `frappe.passkeys.manage`
# (passkey_desk.bundle.js, loaded via app_include_js) and are pure form glue.
doctype_js = {
	"User": "public/js/user_passkeys.js",
	"Passkey Settings": "public/js/passkey_settings.js",
}

# Installation
# ------------
# Version floor + fresh-install-onto-native-core refusal (DESIGN-v1 §14): the
# before_install placement is load-bearing — an after_install raise would leave
# a half-installed, registered app.
before_install = ["passkeys.install.before_install"]
after_install = ["passkeys.install.after_install"]

# Uninstallation
# --------------
before_uninstall = ["passkeys.install.before_uninstall"]

# Migration
# ---------
# Programmatic registry Property Setter — never a fixtures/ fixture (§14).
after_migrate = ["passkeys.install.sync_registry_fixture"]

# Website integration
# -------------------
# Conditional login-page asset delivery (§5.1): the shim appends the login
# bundle to web_include_js/css only on /login when a passkey mode is enabled —
# zero template fork, zero bytes on disabled sites. Import-clean (no webauthn),
# since update_website_context fires on every website render (§1.3). The login
# endpoints are whitelisted (passkeys.passkey.*), so they need no hook here.
update_website_context = ["passkeys.shims.login_page.website_context"]

# Boot
# ----
# Desk boot flag (§8.1): publishes bootinfo.passkeys = {modes, credential_count,
# nudge_state, post_login_method} the desk management + nudge surfaces read.
# Guest/CORE_NATIVE no-op + exception-hardened + import-clean (fires on every Desk
# boot, §1.3). The frontend desk bundle (doctype_js / app_include_js) is wired by
# the integration pass per the frontend manifest — not guessed here.
extend_bootinfo = ["passkeys.boot.extend_bootinfo"]

# Session lifecycle
# -----------------
# passkey_only_login veto (§9.3 / F2): fires BEFORE make_session inside
# post_login on all three branches — a raising hook aborts the login before any
# session exists. Blocks password / email-link / social first-factor login for a
# flagged user; passkey legs (which set frappe.local.flags.passkey_login) and
# impersonation (non-Guest session at hook time) pass. On the every-login hook
# path, so auth_hooks.py imports no webauthn (§1.3).
on_login = ["passkeys.auth_hooks.on_login_veto"]

# Sudo-window seed at fresh login (§7.1): fires after make_session inside
# post_login, where the sid already exists (the on_login veto, §9.3, fires
# BEFORE make_session and cannot seed a sid-keyed window). Dropped on logout
# (§7.5). Both handlers are on the every-login hook path, so session.py imports
# no webauthn (§1.3).
on_session_creation = ["passkeys.session.seed_sudo_window"]
on_logout = ["passkeys.session.clear_sudo_window"]

# Document Events
# ---------------
doc_events = {
	"User": {
		# Without this cascade, Link integrity blocks User deletion (§2.2).
		"on_trash": "passkeys.passkey.cascade_delete_user_artifacts",
	},
	"System Settings": {
		# Reverse half of the two-way 2FA floor (§6.1 / B-F7): refuse flipping
		# enable_two_factor_auth 1→0 while passkey_as_second_factor is on. The
		# forward half lives in the Passkey Settings validator. Import-clean —
		# guard_system_settings never imports webauthn (§1.3).
		"validate": "passkeys.auth_hooks.guard_system_settings",
	},
}
