# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""``update_website_context`` shim — delivers the portal enrollment-nudge bundle on
**every authenticated website render**, not only ``/passkeys``. ``passkey_portal.bundle.js`` is mandated "on authenticated web pages when
enabled (portal nudge + the ``/passkeys`` page component; self-gates further at
runtime)": a portal-only user who never opens ``/passkeys`` would otherwise never
see the enrollment nudge, killing the adoption lever for them. The page
controller (``www/passkeys.py``) keeps delivering the bundle page-scoped on
``/passkeys`` itself; this shim carries it to the *other* authenticated portal
pages.

**Same bundle, self-gating:** we append the identical
``www.passkeys.PORTAL_JS`` / ``PORTAL_CSS`` set the ``/passkeys`` page ships — one
bundle, not a parallel nudge-only build. ``passkey_portal.bundle.js`` requires both
``frappe.passkeys_common`` and ``frappe.passkeys_manage_common`` globals (its
top-level guard bails without them), so the two common files ride along. The bundle
then self-gates client-side: it renders the management cards only where a
``#passkey-portal-root`` mount exists (i.e. ``/passkeys``) and, everywhere else,
runs only ``maybeNudgeBanner`` — which itself no-ops unless the server's cadence
verdict (``frappe.boot.passkeys.nudge_state.eligible``) says show. A
nudge-ineligible page therefore does ~zero extra work over the cached static assets.

**Boot bridge:** website renders build ``frappe.boot`` from
``website/utils.get_boot_data()``, which does **not** run ``extend_bootinfo`` and so
carries no ``passkeys`` key (that path is Desk-only; ``/passkeys`` bridges it in its
own template). The nudge reads the server cadence verdict off
``frappe.boot.passkeys``, so this shim injects ``build_passkeys_boot(user)`` into
``context.boot`` — the SAME single contract the Desk boot flag and the ``/passkeys``
controller expose (``boot.build_passkeys_boot``). ``base.html`` renders
``context.boot`` into ``frappe.boot``.

**Cheap on every render:** the hook fires on EVERY website render, so the
gate is ordered cheapest-first — dormant (cached) → Guest (free, in-memory) →
already-delivered on ``/passkeys`` (free list check) → any-mode-enabled (one cached
settings read, shared with the login shim). Only an authenticated user on a
passkey-enabled site reaches ``build_passkeys_boot`` (a handful of indexed reads —
the same cost the Desk already pays per boot). Guests and disabled sites pay at most
one cached read. Import-clean (no ``webauthn``, directly or transitively — every leg
of ``build_passkeys_boot`` is webauthn-free by construction) and
exception-hardened: a failure here degrades to a nudge-less page, never a broken one.
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
