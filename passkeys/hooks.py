app_name = "passkeys"
app_title = "Passkeys"
app_publisher = "Frappe Passkeys Contributors"
app_description = "Passkey (WebAuthn) authentication for Frappe"
app_email = "hi@andrometiq.com"
app_license = "MIT"

# Desk assets. Order is load-bearing: each bundle reads globals set by the ones above it
# (passkey_common → manage_common → headless → confirm → desk). Bare bundle names let
# core's bundled_asset() resolve content-hashed filenames. The confirm client ships
# regardless of login modes (@passkey_protected is re-auth, not login); the desk bundle
# self-gates on `frappe.boot.passkeys.enabled`.
app_include_js = [
	"passkey_common.bundle.js",
	"passkey_manage_common.bundle.js",
	"passkey_headless.bundle.js",
	"passkey_confirm.bundle.js",
	"passkey_desk.bundle.js",
]
app_include_css = [
	"passkey_confirm.bundle.css",
	"passkey_manage.bundle.css",
]

# User form: the "Passkeys" section. Passkey Settings form: banners + RP-ID confirm.
doctype_js = {
	"User": "public/js/user_passkeys.js",
	"Passkey Settings": "public/js/passkey_settings.js",
}

# Installation
# ------------
# The native-core refusal runs before_install: an after_install raise would leave a
# half-installed, registered app.
before_install = ["passkeys.install.before_install"]
after_install = ["passkeys.install.after_install"]

# Uninstallation
# --------------
before_uninstall = ["passkeys.install.before_uninstall"]

# Migration
# ---------
after_migrate = ["passkeys.install.sync_user_form_section"]

# Website integration: the login bundle on /login and the portal bundle + boot bridge on
# authenticated portal pages, only when a passkey mode is on. Every website render runs
# these, so both shims are webauthn-free and exception-hardened.
update_website_context = [
	"passkeys.shims.login_page.website_context",
	"passkeys.shims.portal_nudge.website_context",
]

# Boot: publishes bootinfo.passkeys (see boot.build_passkeys_boot). Every Desk boot.
extend_bootinfo = ["passkeys.boot.extend_bootinfo"]

# Core OTP login omits usr and clears site cache before the on_login veto consumes this marker.
persistent_cache_keys = ["passkeys:otp-fallback:"]

# Session lifecycle
# -----------------
# Login veto: blocks non-passkey first-factor logins for a passkey_only_login user and
# enforces passkey-as-second-factor for enrolled users. It fires BEFORE make_session
# inside post_login on all three branches, so a raise aborts the login before any
# session exists. Passkey legs pass; otherwise only same-user re-auth or a request
# dispatched to core's exact impersonate method is exempt.
on_login = ["passkeys.auth_hooks.on_login_veto"]

# Sudo-window seed: after make_session, where the sid already exists (the on_login veto
# runs before it and cannot seed a sid-keyed window). Dropped on logout.
on_session_creation = ["passkeys.session.seed_sudo_window"]
on_logout = ["passkeys.session.clear_sudo_window"]

# UI-test sites only (passkeys_deterministic_test_cookies): drop stale sid cookie
# re-seeds. A dict lookup elsewhere. See cookie_determinism.py.
after_request = ["passkeys.cookie_determinism.strip_stale_sid_reseed"]

# Document Events
# ---------------
doc_events = {
	"User": {
		# Without this cascade, Link integrity blocks User deletion.
		"on_trash": "passkeys.passkey.cascade_delete_user_artifacts",
		"before_rename": "passkeys.passkey.refuse_enrolled_user_merge",
		"after_rename": "passkeys.passkey.rename_user_artifacts",
	},
	"System Settings": {
		# Reverse halves of the Passkey Settings floors: refuse enable_two_factor_auth
		# 1→0 while passkey_as_second_factor is on, and disable_user_pass_login 0→1
		# while it is the only passkey mode.
		"validate": "passkeys.auth_hooks.guard_system_settings",
	},
}
