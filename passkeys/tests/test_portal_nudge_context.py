# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Portal enrollment-nudge delivery on authenticated website renders.
``shims/portal_nudge.website_context`` carries the portal bundle +
the ``frappe.boot.passkeys`` bridge to EVERY authenticated portal page (not only
``/passkeys``), so a portal-only user who never opens ``/passkeys`` still meets the
adoption nudge. Mirrors the login-shim ``website_context`` test idiom
(``test_dormancy.test_website_context_appends_no_login_bundle``); the dormant no-op
leg lives with the other hook no-ops in ``test_dormancy.py``."""

import frappe

from passkeys.install import DEFAULTS_PARENT
from passkeys.shims import portal_nudge
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_user
from passkeys.www.passkeys import PORTAL_CSS, PORTAL_JS

RP_ID = "example.com"

_SETTINGS_FIELDS = (
	"passkey_rp_id",
	"passkey_origins",
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_enrollment_policy",
	"passkey_nudge_max_prompts",
	"passkey_nudge_cooldown_days",
)


class PortalNudgeContextTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1  # a first-factor mode on ⇒ any-mode gate true
		settings.passkey_as_second_factor = 0
		settings.passkey_enrollment_policy = "Nudge"
		settings.passkey_nudge_max_prompts = 3
		settings.passkey_nudge_cooldown_days = 30
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		for field in _SETTINGS_FIELDS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"}
		)
		return user

	def _ctx(self, path="app/dashboard", **kw):
		"""A minimal website-render context: ``get_website_settings`` always seeds
		``context.boot`` (the base template renders it into ``frappe.boot``)."""
		return frappe._dict(path=path, boot=frappe._dict(), **kw)

	# (a) authed portal render on a NON-/passkeys route, a mode on ⇒ the full portal
	#     bundle set (one self-gating bundle) + the server cadence verdict.
	def test_authed_portal_render_carries_nudge_bundle(self):
		user = self._user()
		frappe.set_user(user)
		ctx = self._ctx()
		portal_nudge.website_context(ctx)
		js = ctx.get("web_include_js", [])
		for asset in PORTAL_JS:  # common + manage_common + portal.bundle (order load-bearing)
			self.assertIn(asset, js)
		for asset in PORTAL_CSS:
			self.assertIn(asset, ctx.get("web_include_css", []))
		# boot bridge: frappe.boot.passkeys.nudge_state.eligible is the SERVER verdict
		pk = ctx.boot.get("passkeys")
		self.assertIsNotNone(pk)
		self.assertIn("eligible", pk["nudge_state"])
		self.assertTrue(pk["nudge_state"]["eligible"])  # fresh user, 0 creds, knob on

	# (d) SECURITY: the per-user boot payload (credential_count / nudge_state) must never
	#     enter Frappe's shared, path-keyed website page cache and be served to another
	#     user. The render is marked no-cache, and the session CSRF token is NOT baked into
	#     context.boot — core delivers it post-cache via frappe.csrf_token, so it never
	#     lands in cached HTML (regression guard for the cross-user cache-poisoning class).
	def test_authed_portal_render_is_no_cache_and_omits_csrf(self):
		self.addCleanup(setattr, frappe.local, "no_cache", False)
		frappe.local.no_cache = False
		user = self._user()
		frappe.set_user(user)
		ctx = self._ctx()
		portal_nudge.website_context(ctx)
		# the per-user payload was injected ...
		self.assertIsNotNone(ctx.boot.get("passkeys"))
		# ... so the response must be uncacheable (no cross-user cache poisoning) ...
		self.assertTrue(getattr(frappe.local, "no_cache", False))
		# ... and the live session CSRF token must NOT be in the (potentially cached) boot.
		self.assertNotIn("csrf_token", ctx.boot)

	# (b) Guest render ⇒ zero passkey bytes (the nudge is authenticated-only).
	def test_guest_render_ships_no_bundle(self):
		frappe.set_user("Guest")
		ctx = self._ctx()
		portal_nudge.website_context(ctx)
		self.assertNotIn("web_include_js", ctx)  # returns before touching the list
		self.assertNotIn("passkeys", ctx.boot)

	# (c) both modes off ⇒ nothing appended (the any-mode gate).
	def test_modes_off_ships_no_bundle(self):
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		user = self._user()
		frappe.set_user(user)
		ctx = self._ctx()
		portal_nudge.website_context(ctx)
		self.assertFalse(any("passkey_portal" in a for a in ctx.get("web_include_js", [])))
		self.assertNotIn("passkeys", ctx.boot)  # no boot build on a disabled site

	# (e) /passkeys itself already carries the bundle (via get_context) + its own boot
	#     bridge (via the template) ⇒ no duplicate append and no redundant boot rebuild.
	def test_no_double_inject_on_passkeys_page(self):
		user = self._user()
		frappe.set_user(user)
		ctx = self._ctx(path="passkeys", web_include_js=list(PORTAL_JS), web_include_css=list(PORTAL_CSS))
		portal_nudge.website_context(ctx)
		self.assertEqual(ctx.web_include_js, list(PORTAL_JS))  # unchanged — no duplicates
		self.assertEqual(ctx.web_include_css, list(PORTAL_CSS))
		self.assertNotIn("passkeys", ctx.boot)  # short-circuited before the boot build
