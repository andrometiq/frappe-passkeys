# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Portal ``/passkeys`` management page controller (DESIGN-v1 §8.1). Website
users manage their passkeys with the same card component the Desk User form
uses, driven by the whitelisted management endpoints
(``passkeys.api.credentials.*`` + ``passkeys.passkey.get_signal_data`` /
``record_nudge``). Guests are redirected to login.

**Ownership seam:** the Jinja template (``passkeys.html``) is owned by the
frontend bundle; this controller supplies context + the guest guard only. The
context mirrors the Desk ``bootinfo.passkeys`` shape (``boot.build_passkeys_boot``)
so the card component reads one contract on both surfaces. On the core merge this
moves to ``frappe/www/passkeys.py`` verbatim (§11).

``webauthn`` is never imported here (this is a website-render path, §1.3)."""

import frappe

from passkeys import boot

no_cache = 1

# The portal management bundle (frontend manifest §2.5). Order is load-bearing:
# passkey_common.js sets the confirm engine + JSON-shim globals, passkey_manage_
# common.js sets the shared card view-models, and passkey_portal.bundle.js reads
# BOTH and mounts into ``#passkey-portal-root``. Delivered page-scoped here (not via
# the login-page shim) so no other portal page pays for it (§5.1). Portal pages ship
# no ``frappe.ui.Dialog`` / desk confirm bundle, so passkey_common.js is required.
PORTAL_JS = (
	"/assets/passkeys/js/passkey_common.js",
	"/assets/passkeys/js/passkey_manage_common.js",
	"/assets/passkeys/js/passkey_portal.bundle.js",
)
PORTAL_CSS = ("/assets/passkeys/css/passkey_manage.css",)


def get_context(context):
	"""Guest ⇒ redirect to login (``/login?redirect-to=/passkeys``, §8.1). Otherwise
	expose ``context.passkeys`` = the server-truth boot payload the card component
	consumes (enabled, modes, credential_count, nudge_state, post_login_method,
	conditional_create, upsell_eligible, settings_context, rp_id) and append the
	portal management assets. Server state only — nothing client-supplied is echoed."""
	if frappe.session.user in ("Guest", None, ""):
		frappe.local.flags.redirect_location = "/login?redirect-to=/passkeys"
		raise frappe.Redirect

	context.no_cache = 1
	context.passkeys = boot.build_passkeys_boot(frappe.session.user)

	js = context.setdefault("web_include_js", [])
	for asset in PORTAL_JS:
		if asset not in js:
			js.append(asset)
	css = context.setdefault("web_include_css", [])
	for asset in PORTAL_CSS:
		if asset not in css:
			css.append(asset)
	return context
