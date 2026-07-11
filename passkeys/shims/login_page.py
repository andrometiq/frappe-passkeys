# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""``update_website_context`` shim — conditionally couples the login bundle to
core's login page with **zero template fork**. Appends the
built asset paths to ``context.web_include_js`` / ``web_include_css`` only on
the ``/login`` page **and** only when a passkey login mode is enabled, so
disabled sites ship zero extra bytes and every other page is untouched.

**Hook-path import discipline:** this runs on **every** website render,
so it MUST NOT import ``webauthn`` (directly or transitively). It imports only
``frappe`` + the webauthn-free settings read, and is exception-hardened — a
failure here degrades to a passkey-less login page, never a broken one.
"""

import frappe
from frappe.utils import cint

from passkeys import install

# Served statically from the app's public/ tree at /assets/passkeys/… . The
# login bundle is a plain IIFE (no ES imports), so it needs no esbuild entry;
# referencing the full /assets path bypasses the bundle map entirely and is
# build-map-free. Order is load-bearing: passkey_common.js sets the
# `frappe.passkeys_common` global the bundle reads (frontend notes).
LOGIN_JS = (
	"/assets/passkeys/js/passkey_common.js",
	"/assets/passkeys/js/passkey_login.bundle.js",
)
LOGIN_CSS = ("/assets/passkeys/css/passkey_login.css",)


def website_context(context) -> None:
	"""Append the passkey login assets on the login page when any mode is on."""
	try:
		if install.dormant():
			return  # dormant-shell: append no login bundle — the /login page ships
			# zero passkey bytes, so there is nothing client-side to self-remove
		if context.get("path") != "login":
			return
		if not _any_login_mode_enabled():
			return
		context.setdefault("web_include_js", [])
		for asset in LOGIN_JS:
			if asset not in context["web_include_js"]:
				context["web_include_js"].append(asset)
		context.setdefault("web_include_css", [])
		for asset in LOGIN_CSS:
			if asset not in context["web_include_css"]:
				context["web_include_css"].append(asset)
	except Exception:
		frappe.log_error(title="passkeys: login-page website_context failed")


def _any_login_mode_enabled() -> bool:
	"""True iff `login_with_passkey` or `passkey_as_second_factor` is on (any-mode
	gate). Webauthn-free settings read; fail-closed on any error."""
	try:
		settings = frappe.get_cached_doc("Passkey Settings")
		return bool(cint(settings.login_with_passkey) or cint(settings.passkey_as_second_factor))
	except Exception:
		return False
