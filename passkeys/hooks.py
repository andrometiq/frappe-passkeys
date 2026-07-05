app_name = "passkeys"
app_title = "Passkeys"
app_publisher = "Frappe Passkeys Contributors"
app_description = "Passkey (WebAuthn) authentication for Frappe"
app_email = "passkeys@example.com"
app_license = "MIT"

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

# Session lifecycle
# -----------------
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
