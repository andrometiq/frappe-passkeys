# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Portal ``/passkeys`` management page controller. Website
users manage their passkeys with the same card component the Desk User form
uses, driven by the whitelisted management endpoints
(``passkeys.api.credentials.*`` + ``passkeys.passkey.get_signal_data`` /
``record_nudge``). Guests are redirected to login.

**Ownership seam:** the Jinja template (``passkeys.html``) is owned by the
frontend bundle; this controller supplies context + the guest guard only. The
context mirrors the Desk ``bootinfo.passkeys`` shape (``boot.build_passkeys_boot``)
so the card component reads one contract on both surfaces. On the core merge this
moves to ``frappe/www/passkeys.py`` verbatim.

``webauthn`` is never imported here (this is a website-render path)."""

import frappe
from frappe.sessions import get_csrf_token

from passkeys import boot, install

no_cache = 1

# The portal management bundle (frontend manifest). Referenced by BARE bundle name
# (no /assets prefix) so core's bundled_asset() resolves each to its content-hashed
# filename from assets.json — the browser revalidates on every deploy instead of
# serving a stale cached copy (an /assets-prefixed path would bypass the hash map).
# Order is load-bearing: passkey_common.bundle.js sets the confirm engine + JSON-shim
# globals, passkey_manage_common.bundle.js sets the shared card view-models,
# passkey_headless.bundle.js sets the markup-free lifecycle API
# (``frappe.passkeys.headless`` — the add-passkey ceremony the card engine calls), and
# passkey_portal.bundle.js reads these and mounts into ``#passkey-portal-root``.
# Delivered page-scoped here for the /passkeys management page; the SAME set also
# reaches other authenticated portal pages via ``shims/portal_nudge.py`` so the nudge
# finds portal-only users ("on authenticated web pages when enabled"), where the bundle
# self-gates to the nudge alone (no mount). Portal pages ship no ``frappe.ui.Dialog`` /
# desk confirm bundle, so passkey_common.bundle.js is required.
PORTAL_JS = (
	"passkey_common.bundle.js",
	"passkey_manage_common.bundle.js",
	"passkey_headless.bundle.js",
	"passkey_portal.bundle.js",
)
PORTAL_CSS = ("passkey_manage.bundle.css",)


def get_context(context):
	"""Guest ⇒ redirect to login (``/login?redirect-to=/passkeys``). Otherwise
	expose ``context.passkeys`` = the server-truth boot payload the card component
	consumes (enabled, modes, credential_count, nudge_state, post_login_method,
	conditional_create, upsell_eligible, settings_context, rp_id) and append the
	portal management assets. Server state only — nothing client-supplied is echoed."""
	if install.dormant():
		# dormant-shell: the app must not shadow core's native /passkeys — this
		# UI surface goes dark (404) instead of rendering a parallel management page.
		raise frappe.DoesNotExistError(frappe._("Passkeys are served natively by this site."))
	if frappe.session.user in ("Guest", None, ""):
		frappe.local.flags.redirect_location = "/login?redirect-to=/passkeys"
		raise frappe.Redirect

	context.no_cache = 1
	context.csrf_token = get_csrf_token()
	context.passkeys = boot.build_passkeys_boot(frappe.session.user)
	if isinstance(context.get("boot"), dict):
		context.boot["csrf_token"] = context.csrf_token
		context.boot["passkeys"] = context.passkeys

	js = context.setdefault("web_include_js", [])
	for asset in PORTAL_JS:
		if asset not in js:
			js.append(asset)
	css = context.setdefault("web_include_css", [])
	for asset in PORTAL_CSS:
		if asset not in css:
			css.append(asset)
	return context
