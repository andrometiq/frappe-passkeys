# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin enrollment-enforcement recovery endpoints (F2 polish): the per-user one-click
exemption (via the lazily-created ``Passkey Enforcement Exempt`` role) and the admin
grace-counter reset, both System-Manager-gated + rate-limited."""

import frappe

from passkeys import boot, enforcement_admin
from passkeys.enforcement_admin import EXEMPT_ROLE
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_user

RP_ID = "example.com"

_FIELDS = (
	"passkey_rp_id",
	"passkey_origins",
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_enrollment_policy",
	"passkey_enforce_after",
	"passkey_enforce_scope",
	"passkey_enforce_privileged_always",
	"passkey_enforce_grace_logins",
	"passkey_enforce_incapable",
	"passkey_enforce_allow_hybrid",
)


class EnforcementAdminTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		# The lazily-created role survives the _restore commit, so purge it (and every
		# assignment) at the top of each test — keeps the "role doesn't exist yet"
		# precondition true regardless of test order.
		self._purge_exempt_role()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = "https://example.com"
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enrollment_policy = "Enforce"
		settings.passkey_enforce_after = None
		settings.passkey_enforce_scope = "All Users"
		settings.passkey_enforce_privileged_always = 1
		settings.passkey_enforce_grace_logins = 3
		settings.passkey_enforce_incapable = "Degrade to Nudge"
		settings.passkey_enforce_allow_hybrid = 1
		settings.set("passkey_enforce_roles", [])
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		# Mirrors test_enforcement: the settings write must be restored + committed so the
		# modes-on state never leaks (some legs commit past the per-test savepoint). Also
		# strip our lazily-added exempt role so the fixture is clean.
		frappe.set_user("Administrator")
		doc = frappe.get_doc("Passkey Settings")
		for field in _FIELDS:
			doc.set(field, self._snapshot.get(field))
		doc.set("passkey_enforce_roles", [])
		# Restore the exact pre-test snapshot without re-validating it. A UI test may
		# have installed an HTTP-only development origin that is valid only through
		# its guarded helper; cleanup must not become order-dependent on that state.
		doc.set_parent_in_children()
		doc.set_name_in_children()
		doc.update_single(doc.get_valid_dict())
		doc.update_children()
		self._purge_exempt_role()
		flush_settings_cache()
		frappe.db.commit()

	def _purge_exempt_role(self):
		frappe.db.delete("Has Role", {"role": EXEMPT_ROLE})
		if frappe.db.exists("Role", EXEMPT_ROLE):
			frappe.delete_doc("Role", EXEMPT_ROLE, force=1, ignore_permissions=True)

	def _user(self, roles=None) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_enforce"}
		)
		if roles:
			frappe.get_doc("User", user).add_roles(*roles)
		return user

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _in_scope(self, user) -> bool:
		return boot._user_in_enforce_scope(user, self._settings())

	# ---- one-click exemption --------------------------------------------

	def test_exempt_creates_role_lazily_and_flips_scope(self):
		self.assertFalse(
			frappe.db.exists("Role", EXEMPT_ROLE), "role must not exist before the first exemption"
		)
		user = self._user()
		self.assertTrue(self._in_scope(user))  # enforced by default

		view = enforcement_admin.set_user_exemption(user, True)

		self.assertTrue(frappe.db.exists("Role", EXEMPT_ROLE), "role is created lazily on first exemption")
		# no obsolete role-wide settings row is created
		self.assertFalse(
			frappe.db.exists(
				"Passkey Enforcement Role",
				{"parent": "Passkey Settings", "parentfield": "passkey_enforce_exempt_roles"},
			)
		)
		# role assigned to the user, and the scope verdict flips
		self.assertIn(EXEMPT_ROLE, set(frappe.get_roles(user)))
		self.assertFalse(self._in_scope(user))
		self.assertTrue(view["exempt"])
		self.assertFalse(view["in_scope"])

	def test_unexempt_removes_only_the_assignment(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		self.assertFalse(self._in_scope(user))

		view = enforcement_admin.set_user_exemption(user, False)

		# assignment gone, user back in scope
		self.assertNotIn(EXEMPT_ROLE, set(frappe.get_roles(user)))
		self.assertTrue(self._in_scope(user))
		self.assertFalse(view["exempt"])
		self.assertTrue(view["in_scope"])
		# marker role LEFT in place for reuse; no settings row exists
		self.assertTrue(frappe.db.exists("Role", EXEMPT_ROLE))
		self.assertFalse(
			frappe.db.exists(
				"Passkey Enforcement Role",
				{"parent": "Passkey Settings", "parentfield": "passkey_enforce_exempt_roles"},
			)
		)

	def test_exempt_is_idempotent_no_duplicate_rows(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		enforcement_admin.set_user_exemption(user, True)  # double-click

		# no duplicate Has Role row on the user
		has_role = frappe.get_all(
			"Has Role", filters={"parent": user, "role": EXEMPT_ROLE, "parenttype": "User"}
		)
		self.assertEqual(len(has_role), 1)
		self.assertFalse(
			frappe.db.exists(
				"Passkey Enforcement Role",
				{"parent": "Passkey Settings", "parentfield": "passkey_enforce_exempt_roles"},
			)
		)

	def test_exempt_accepts_documented_boolean_forms(self):
		user = self._user()
		for value in (True, 1, "1", "true", "yes", "on"):
			with self.subTest(value=value):
				enforcement_admin.set_user_exemption(user, value)
				self.assertIn(EXEMPT_ROLE, set(frappe.get_roles(user)))
		for value in (False, 0, "0", "false", "no", "off"):
			with self.subTest(value=value):
				enforcement_admin.set_user_exemption(user, value)
				self.assertNotIn(EXEMPT_ROLE, set(frappe.get_roles(user)))

	def test_malformed_exemption_value_does_not_revoke(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		for value in (None, "", "maybe", 2, 0.0, [], {}):
			with self.subTest(value=value):
				with self.assertRaises(frappe.ValidationError):
					enforcement_admin.set_user_exemption(user, value)
				self.assertIn(EXEMPT_ROLE, set(frappe.get_roles(user)))

	# ---- grace reset ----------------------------------------------------

	def test_reset_restores_full_grace_budget(self):
		user = self._user()
		for _ in range(3):
			boot.record_enforcement_event(user, "defer")
		self.assertTrue(boot.build_enforcement(user, self._settings(), 0)["blocking"])

		view = enforcement_admin.reset_enforcement_grace(user)

		v = boot.build_enforcement(user, self._settings(), 0)
		self.assertFalse(v["blocking"])
		self.assertEqual(v["grace_remaining"], 3)
		self.assertEqual(view["grace_remaining"], 3)
		self.assertEqual(view["grace_used"], 0)
		# the storage row is gone (fresh zero-state), not a lingering grace_used=0 row
		self.assertFalse(
			frappe.db.exists("DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_enforce"})
		)

	def test_reset_is_idempotent(self):
		user = self._user()
		boot.record_enforcement_event(user, "defer")
		enforcement_admin.reset_enforcement_grace(user)
		# second reset on an already-clean counter is a no-op, still full budget
		view = enforcement_admin.reset_enforcement_grace(user)
		self.assertEqual(view["grace_remaining"], 3)
		self.assertEqual(view["grace_used"], 0)

	# ---- read view-model ------------------------------------------------

	def test_view_reports_satisfied_and_grace(self):
		user = self._user()
		make_credential(user)
		boot.record_enforcement_event(user, "defer")
		view = enforcement_admin.get_user_enforcement_admin(user)
		self.assertTrue(view["in_scope"])
		self.assertEqual(view["credential_count"], 1)
		self.assertEqual(view["grace_used"], 1)
		self.assertEqual(view["grace_total"], 3)
		self.assertFalse(view["exempt"])
		self.assertTrue(view["enforcing"])

	def test_view_keeps_privileged_user_in_scope_without_an_exemption(self):
		user = self._user(roles=["System Manager"])
		view = enforcement_admin.get_user_enforcement_admin(user)
		self.assertFalse(view["exempt"])
		self.assertNotIn("exempt_via_other_role", view)
		self.assertTrue(view["in_scope"])

	# ---- authorization (System-Manager gate) ----------------------------

	def test_endpoints_are_system_manager_gated(self):
		user = self._user()
		# v15's frappe.only_for is a no-op while flags.in_test is set (v16+ dropped that
		# short-circuit); clear it so the real System Manager gate is exercised.
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.set_user(user)  # a plain user, no System Manager
		frappe.flags.in_test = False
		try:
			with self.assertRaises(frappe.PermissionError):
				enforcement_admin.get_user_enforcement_admin(user)
			with self.assertRaises(frappe.PermissionError):
				enforcement_admin.set_user_exemption(user, True)
			with self.assertRaises(frappe.PermissionError):
				enforcement_admin.reset_enforcement_grace(user)
		finally:
			frappe.flags.in_test = saved_in_test
			frappe.set_user("Administrator")
		# nothing leaked: the role was never created, the user never exempted
		self.assertNotIn(EXEMPT_ROLE, set(frappe.get_roles(user)))

	def test_unknown_user_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			enforcement_admin.set_user_exemption("does-not-exist@example.com", True)
