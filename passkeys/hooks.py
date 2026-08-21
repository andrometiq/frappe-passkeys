app_name = "passkeys"
app_title = "Passkeys"
app_publisher = "Frappe Passkeys Contributors"
app_description = "Passkey (WebAuthn) authentication for Frappe"
app_email = "hi@andrometiq.com"
app_license = "MIT"

# Desk / portal assets — action-confirmation ("passkey signing") client
# ---------------------------------------------------------------------------
# The confirm.* surface is delivered on EVERY desk page independent of login
# modes: consuming apps' @passkey_protected actions must not
# silently break when an admin toggles login modes — it is re-auth, not login.
# passkey_common.bundle.js MUST load first (sets the frappe.passkeys_common global the
# confirm bundle reads). Every entry is referenced by BARE bundle name (no /assets
# prefix) so core's bundled_asset() resolves each to its content-hashed filename from
# assets.json — an /assets-prefixed path would BYPASS the hash map and be served raw
# (uncache-busted). The files are UMD-lite browser globals; they self-gate on
# `frappe.passkeys` availability at runtime.
#
# Desk management surfaces (frontend). Order is load-bearing:
# passkey_manage_common.bundle.js sets `frappe.passkeys_manage_common`,
# passkey_headless.bundle.js sets `frappe.passkeys.headless` (the markup-free public
# lifecycle API, loaded after the two shared libs it reads), and
# passkey_confirm.bundle.js sets `frappe.passkeys.call`/`.confirm`;
# passkey_desk.bundle.js reads these, so they must load before it (frontend
# manifest). The desk bundle self-gates on `frappe.boot.passkeys.enabled` — a
# both-modes-off / dormant site removes itself.
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

# Passkey management is NOT a first-class avatar-menu item. It lives in the
# "Passkeys" section of the User form (My Settings) via doctype_js below — the
# natural, discoverable Settings home, with full manage capability (list / add /
# rename / remove). The previously-synced "My Passkeys" navbar item is cleaned up
# idempotently by after_migrate (install.sync_standard_navbar_items) on existing
# sites. openManagerDialog() is retained for programmatic CTAs/nudges.

# DocType client scripts (frontend)
# --------------------------------------------------
# User form: the "Passkeys" section (own form ⇒ interactive cards + add; another
# user's form, System Manager ⇒ read-only inventory + WebAuthn Credential link).
# Passkey Settings form: the cross-flag banner matrix + the RP-ID
# one-way-door confirm. Both delegate rendering to `frappe.passkeys.manage`
# (passkey_desk.bundle.js, loaded via app_include_js) and are pure form glue.
doctype_js = {
	"User": "public/js/user_passkeys.js",
	"Passkey Settings": "public/js/passkey_settings.js",
}

# Installation
# ------------
# Version floor + fresh-install-onto-native-core refusal: the
# before_install placement is load-bearing — an after_install raise would leave
# a half-installed, registered app.
before_install = ["passkeys.install.before_install"]
after_install = ["passkeys.install.after_install"]

# Uninstallation
# --------------
before_uninstall = ["passkeys.install.before_uninstall"]

# Migration
# ---------
# Remove an obsolete development-build Property Setter, then sync live UI fields.
after_migrate = [
	"passkeys.install.cleanup_legacy_registry_property_setter",
	"passkeys.install.sync_standard_navbar_items",
	"passkeys.install.sync_user_form_section",
]

# Website integration
# -------------------
# Conditional login-page asset delivery: the shim appends the login
# bundle to web_include_js/css only on /login when a passkey mode is enabled —
# zero template fork, zero bytes on disabled sites. Import-clean (no webauthn),
# since update_website_context fires on every website render. The login
# endpoints are whitelisted (passkeys.passkey.*), so they need no hook here.
#
# Portal enrollment-nudge delivery ("on authenticated web pages"):
# the second shim carries the portal bundle + the frappe.boot.passkeys bridge to
# EVERY authenticated portal page (not only /passkeys), so a portal-only user who
# never opens /passkeys still gets the adoption nudge. Same one bundle, which
# self-gates at runtime; gate is cheapest-first + import-clean + exception-hardened.
update_website_context = [
	"passkeys.shims.login_page.website_context",
	"passkeys.shims.portal_nudge.website_context",
]

# Boot
# ----
# Desk boot flag: publishes bootinfo.passkeys = {modes, credential_count,
# nudge_state, post_login_method} the desk management + nudge surfaces read.
# Guest/CORE_NATIVE no-op + exception-hardened + import-clean (fires on every Desk
# boot). The frontend desk bundle (doctype_js / app_include_js) is wired by
# the integration pass per the frontend manifest — not guessed here.
extend_bootinfo = ["passkeys.boot.extend_bootinfo"]

# Session lifecycle
# -----------------
# passkey_only_login veto: fires BEFORE make_session inside
# post_login on all three branches — a raising hook aborts the login before any
# session exists. Blocks password / email-link / social first-factor login for a
# flagged user and enforces passkey-as-second-factor for enrolled users. Passkey
# legs pass; otherwise only same-user re-auth or a request dispatched to core's
# exact impersonate method is exempt. On the every-login hook path, so
# auth_hooks.py imports no webauthn.
on_login = ["passkeys.auth_hooks.on_login_veto"]

# Sudo-window seed at fresh login: fires after make_session inside
# post_login, where the sid already exists (the on_login veto fires
# BEFORE make_session and cannot seed a sid-keyed window). Dropped on logout.
# Both handlers are on the every-login hook path, so session.py imports
# no webauthn.
on_session_creation = ["passkeys.session.seed_sudo_window"]
on_logout = ["passkeys.session.clear_sudo_window"]

# UI-test determinism: on sites with the passkeys_deterministic_test_cookies
# flag, drop stale sid cookie re-seeds before they flush, so the browser's
# auth state changes only on genuine login/logout transitions (kills the
# straggler-response sid races the Cypress suite hit on loaded CI runners).
# No-op (one dict lookup) on production sites. See cookie_determinism.py.
after_request = ["passkeys.cookie_determinism.strip_stale_sid_reseed"]

# Document Events
# ---------------
doc_events = {
	"User": {
		# Without this cascade, Link integrity blocks User deletion.
		"on_trash": "passkeys.passkey.cascade_delete_user_artifacts",
	},
	"System Settings": {
		# Reverse half of the two-way 2FA floor: refuse flipping
		# enable_two_factor_auth 1→0 while passkey_as_second_factor is on. The
		# forward half lives in the Passkey Settings validator. Import-clean —
		# guard_system_settings never imports webauthn.
		"validate": "passkeys.auth_hooks.guard_system_settings",
	},
}
