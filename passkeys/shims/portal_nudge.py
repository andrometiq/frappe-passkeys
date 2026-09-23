# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""``update_website_context`` shim: delivers the portal bundle (the same set
``/passkeys`` ships) to every authenticated portal page, so portal-only users who never
open ``/passkeys`` still see the enrollment nudge. The bundle self-gates: cards only on
``#passkey-portal-root``, elsewhere just the nudge, which obeys the server cadence verdict.

Website boot (``get_boot_data``) has no ``extend_bootinfo``, so this shim bridges
``build_passkeys_boot(user)`` into ``context.boot``. Gates run cheapest-first because
every website render calls it; it is webauthn-free and exception-hardened.
"""

import frappe

from passkeys import boot, install
from passkeys.shims.login_page import _any_login_mode_enabled
from passkeys.www.passkeys import PORTAL_CSS, PORTAL_JS


def website_context(context) -> None:
	"""Append the portal nudge bundle + bridge ``frappe.boot.passkeys`` on any
	authenticated portal page when a passkey mode is enabled."""
	try:
		if install.dormant():
			return  # dormant-shell: ship zero passkey bytes — core serves the
			# portal nudge natively, so there is nothing client-side to self-remove
		user = frappe.session.user
		if user in ("Guest", None, ""):
			return  # nudges are authenticated-only; the session-user check is free

		js = context.setdefault("web_include_js", [])
		if any("passkey_portal.bundle" in asset for asset in js):
			return  # The /passkeys controller already delivered the bundle AND
			# its own frappe.boot.passkeys bridge (template) — never double-inject

		if not _any_login_mode_enabled():
			return  # any-mode gate (cached settings read; shared with login_page):
			# a 2FA-only site's users must still be nudged to enroll and manage

		# boot bridge: the nudge reads the SERVER cadence verdict off
		# frappe.boot.passkeys.nudge_state.eligible. Website boot (get_boot_data) omits
		# passkeys, so publish the single boot contract (build_passkeys_boot) into
		# context.boot; base.html renders it into frappe.boot. Only reached for an authed
		# user on an enabled site — the Desk pays the identical build per boot.
		existing_boot = context.get("boot")
		if isinstance(existing_boot, dict) and "passkeys" not in existing_boot:
			# This payload is PER-USER (credential_count / nudge_state), so the render
			# must never enter Frappe's shared, path-keyed website page cache and be
			# served to another user. Mark the response no-cache before injecting.
			# (CSRF is delivered by core's post-cache `<!-- csrf_token -->` bridge —
			# frappe.csrf_token — so it is deliberately NOT injected into the cached boot.)
			frappe.local.no_cache = 1
			existing_boot["passkeys"] = boot.build_passkeys_boot(user)

		# Same bundle set as /passkeys — idempotent append; the bundle self-gates
		# on the #passkey-portal-root mount (cards only there) and the nudge verdict.
		for asset in PORTAL_JS:
			if asset not in js:
				js.append(asset)
		css = context.setdefault("web_include_css", [])
		for asset in PORTAL_CSS:
			if asset not in css:
				css.append(asset)
	except Exception:
		frappe.log_error(title="passkeys: portal-nudge website_context failed")
