# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin enrollment-enforcement recovery endpoints (F2 polish): the per-user one-click
exemption (a per-user ``__passkeys`` flag) and the admin
grace-counter reset, both System-Manager-gated + rate-limited."""

import frappe

from passkeys import boot, enforcement_admin, state
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_user

RP_ID = "example.com"

_FIELDS = (
	"passkey_rp_id",
	"passkey_origins",
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_enforce_after",
	"passkey_enforce_scope",
	"passkey_enforce_privileged_always",
	"passkey_everyone_else",
	"passkey_enforce_grace_logins",
	"passkey_enforce_incapable",
)


class EnforcementAdminTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		# The admin endpoints are rate-limited per user and these tests call them often.
		for endpoint in ("get_user_enforcement_admin", "set_user_exemption", "reset_enforcement_grace"):
			state.clear_counter(f"{state.RATE_LIMIT_PREFIX}{endpoint}:Administrator")
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = "https://example.com"
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enforce_after = None
		settings.passkey_enforce_scope = "All users"
		settings.passkey_enforce_privileged_always = 1
		settings.passkey_everyone_else = "Nudge"
		settings.passkey_enforce_grace_logins = 3
		settings.passkey_enforce_incapable = "Degrade to Nudge"
		settings.set("passkey_enforce_roles", [])
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		# Mirrors test_enforcement: the settings write must be restored + committed so the
		# modes-on state never leaks (some legs commit past the per-test savepoint).
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
		flush_settings_cache()
		frappe.db.commit()

	def _user(self, roles=None) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete,
			"DefaultValue",
			{
				"parent": DEFAULTS_PARENT,
				"defkey": ("in", [f"{user}_passkey_enforce", f"{user}_passkey_exempt"]),
			},
		)
		if roles:
			frappe.get_doc("User", user).add_roles(*roles)
		return user

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _in_scope(self, user) -> bool:
		return boot._user_in_enforce_scope(user, self._settings())

	# ---- one-click exemption --------------------------------------------

	def test_exempt_flips_scope_without_touching_roles(self):
		user = self._user()
		roles_before = set(frappe.get_roles(user))
		self.assertTrue(self._in_scope(user))  # enforced by default

		view = enforcement_admin.set_user_exemption(user, True)

		self.assertTrue(boot.is_exempt(user))
		self.assertEqual(set(frappe.get_roles(user)), roles_before)
		self.assertFalse(self._in_scope(user))
		self.assertTrue(view["exempt"])
		self.assertFalse(view["in_scope"])

	def test_unexempt_puts_the_user_back_in_scope(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		self.assertFalse(self._in_scope(user))

		view = enforcement_admin.set_user_exemption(user, False)

		self.assertFalse(boot.is_exempt(user))
		self.assertTrue(self._in_scope(user))
		self.assertFalse(view["exempt"])
		self.assertTrue(view["in_scope"])

	def test_exempt_is_idempotent_no_duplicate_rows(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		enforcement_admin.set_user_exemption(user, True)  # double-click

		rows = frappe.get_all(
			"DefaultValue", filters={"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_exempt"}
		)
		self.assertEqual(len(rows), 1)

	def test_exemption_survives_a_role_profile_sync(self):
		# Frappe rebuilds a profile-managed user's roles on every save; a role-based
		# marker would be dropped here.
		role = "Passkeys Test Profile Role"
		if not frappe.db.exists("Role", role):
			frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
		self.addCleanup(frappe.delete_doc, "Role", role, force=1, ignore_permissions=True)
		profile = frappe.get_doc({"doctype": "Role Profile", "role_profile": "Passkeys Test Profile"})
		profile.append("roles", {"role": role})
		profile.insert(ignore_permissions=True, ignore_if_duplicate=True)
		self.addCleanup(frappe.delete_doc, "Role Profile", profile.name, force=1, ignore_permissions=True)
		user = self._user()
		user_doc = frappe.get_doc("User", user)
		if user_doc.meta.has_field("role_profiles"):
			user_doc.append("role_profiles", {"role_profile": profile.name})
		else:
			user_doc.role_profile_name = profile.name
		user_doc.save(ignore_permissions=True)

		enforcement_admin.set_user_exemption(user, True)
		frappe.get_doc("User", user).save(ignore_permissions=True)

		self.assertTrue(boot.is_exempt(user))
		self.assertFalse(self._in_scope(user))

	def test_exempt_accepts_documented_boolean_forms(self):
		user = self._user()
		for value in (True, 1, "1", "true", "yes", "on"):
			with self.subTest(value=value):
				enforcement_admin.set_user_exemption(user, value)
				self.assertTrue(boot.is_exempt(user))
		for value in (False, 0, "0", "false", "no", "off"):
			with self.subTest(value=value):
				enforcement_admin.set_user_exemption(user, value)
				self.assertFalse(boot.is_exempt(user))

	def test_malformed_exemption_value_does_not_revoke(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		for value in (None, "", "maybe", 2, 0.0, [], {}):
			with self.subTest(value=value):
				with self.assertRaises(frappe.ValidationError):
					enforcement_admin.set_user_exemption(user, value)
				self.assertTrue(boot.is_exempt(user))

	# ---- grace reset ----------------------------------------------------

	def test_reset_restores_full_grace_budget(self):
		user = self._user()
		for _ in range(3):
			boot.record_enforcement_defer(user)
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
		boot.record_enforcement_defer(user)
		enforcement_admin.reset_enforcement_grace(user)
		# second reset on an already-clean counter is a no-op, still full budget
		view = enforcement_admin.reset_enforcement_grace(user)
		self.assertEqual(view["grace_remaining"], 3)
		self.assertEqual(view["grace_used"], 0)

	# ---- read view-model ------------------------------------------------

	def test_view_reports_satisfied_and_grace(self):
		user = self._user()
		make_credential(user)
		boot.record_enforcement_defer(user)
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
		self.assertFalse(boot.is_exempt(user))

	def test_unknown_user_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			enforcement_admin.set_user_exemption("does-not-exist@example.com", True)
