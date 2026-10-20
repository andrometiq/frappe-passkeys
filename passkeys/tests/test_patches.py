# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Data patches listed in patches.txt."""

import frappe

from passkeys import boot
from passkeys.patches.v15_0 import map_old_enrollment_policy as policy_patch
from passkeys.patches.v15_0 import rename_first_enrollment_setting as rename_patch
from passkeys.tests.committed_state import delete_fixture
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user


class TestRenameFirstEnrollmentSetting(IntegrationTestCase):
	def setUp(self):
		self._value = frappe.db.get_single_value("Passkey Settings", rename_patch.NEW)

	def tearDown(self):
		self._delete(rename_patch.OLD)
		frappe.db.set_single_value("Passkey Settings", rename_patch.NEW, self._value)

	def _delete(self, field):
		frappe.db.sql("delete from `tabSingles` where doctype=%s and field=%s", ("Passkey Settings", field))

	def _rows(self, field):
		return frappe.db.sql(
			"select value from `tabSingles` where doctype=%s and field=%s",
			("Passkey Settings", field),
		)

	def test_old_choice_replaces_the_new_default(self):
		frappe.db.set_single_value("Passkey Settings", rename_patch.NEW, 1)
		self._delete(rename_patch.OLD)
		frappe.db.sql(
			"insert into `tabSingles` (doctype, field, value) values (%s, %s, %s)",
			("Passkey Settings", rename_patch.OLD, "0"),
		)
		rename_patch.execute()
		self.assertEqual(self._rows(rename_patch.OLD), ())
		self.assertEqual([row[0] for row in self._rows(rename_patch.NEW)], ["0"])

	def test_old_enabled_choice_carries_over_and_reruns_are_harmless(self):
		frappe.db.set_single_value("Passkey Settings", rename_patch.NEW, 0)
		self._delete(rename_patch.OLD)
		frappe.db.sql(
			"insert into `tabSingles` (doctype, field, value) values (%s, %s, %s)",
			("Passkey Settings", rename_patch.OLD, "1"),
		)
		rename_patch.execute()
		rename_patch.execute()
		self.assertEqual(self._rows(rename_patch.OLD), ())
		self.assertEqual([row[0] for row in self._rows(rename_patch.NEW)], ["1"])

	def test_no_old_row_leaves_the_new_field_alone(self):
		frappe.db.set_single_value("Passkey Settings", rename_patch.NEW, 1)
		self._delete(rename_patch.OLD)
		rename_patch.execute()
		self.assertEqual([row[0] for row in self._rows(rename_patch.NEW)], ["1"])


class TestMapOldEnrollmentPolicy(IntegrationTestCase):
	FIELDS = (
		"passkey_enrollment_policy",
		"passkey_enforce_scope",
		"passkey_everyone_else",
		"passkey_enforce_after",
		"passkey_enforce_allow_hybrid",
		"passkey_enforce_privileged_always",
	)

	def setUp(self):
		self._saved = self._stored()
		self._saved_exemptions = {
			user: boot.get_default_value(f"{user}_passkey_exempt")
			for (user,) in frappe.db.sql(
				"select distinct parent from `tabHas Role` where parenttype=%s and role=%s",
				("User", "Passkey Enforcement Exempt"),
			)
		}
		self.addCleanup(self._restore)

	def _stored(self):
		return dict(
			frappe.db.sql(
				"select field, value from `tabSingles` where doctype=%s and field in %s",
				("Passkey Settings", self.FIELDS),
			)
		)

	def _restore(self):
		self._seed(self._saved)
		for user, value in self._saved_exemptions.items():
			if value is None:
				boot.set_exempt(user, False)
			else:
				frappe.db.set_default(f"{user}_passkey_exempt", value, parent=boot.DEFAULTS_PARENT)
		frappe.clear_cache(doctype="Passkey Settings")

	def _seed(self, values):
		frappe.db.sql(
			"delete from `tabSingles` where doctype=%s and field in %s", ("Passkey Settings", self.FIELDS)
		)
		for field, value in values.items():
			frappe.db.sql(
				"insert into `tabSingles` (doctype, field, value) values (%s, %s, %s)",
				("Passkey Settings", field, value),
			)

	def _migrate(self, **old):
		self._seed({"passkey_everyone_else": "Nudge", **old})
		policy_patch.execute()
		policy_patch.execute()
		return self._stored()

	def test_old_default_scope_without_enforce_becomes_no_one(self):
		after = self._migrate(
			passkey_enrollment_policy="Nudge",
			passkey_enforce_scope="All Users",
			passkey_enforce_privileged_always="1",
		)
		self.assertEqual(after["passkey_enforce_scope"], "No one")
		self.assertEqual(after["passkey_everyone_else"], "Nudge")
		self.assertNotIn("passkey_enrollment_policy", after)
		frappe.clear_cache(doctype="Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		self.assertFalse(boot._user_in_enforce_scope("Administrator", settings))
		self.assertFalse(boot.is_enforcing(settings))

	def test_old_enforce_keeps_its_scope_and_drops_a_stale_date(self):
		after = self._migrate(
			passkey_enrollment_policy="Enforce",
			passkey_enforce_scope="Selected Roles",
			passkey_enforce_after="2099-01-01",
			passkey_enforce_privileged_always="1",
		)
		self.assertEqual(after["passkey_enforce_scope"], "Selected roles")
		self.assertFalse(after.get("passkey_enforce_after"))
		self.assertEqual(after["passkey_enforce_privileged_always"], "1")

	def test_legacy_role_exemption_survives_migration_and_rerun(self):
		role = "Passkey Enforcement Exempt"
		if not frappe.db.exists("Role", role):
			frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
			self.addCleanup(
				delete_fixture, "Role", role, force=1, ignore_permissions=True, delete_permanently=True
			)
		user = make_user()
		self.addCleanup(
			delete_fixture, "User", user, force=1, ignore_permissions=True, delete_permanently=True
		)
		self.addCleanup(boot.set_exempt, user, False)
		frappe.get_doc("User", user).add_roles(role)
		self.assertFalse(boot.is_exempt(user))
		self._migrate(passkey_enrollment_policy="Enforce", passkey_enforce_scope="All Users")
		self.assertTrue(boot.is_exempt(user))
		self.assertFalse(boot._user_in_enforce_scope(user, frappe.get_doc("Passkey Settings")))
		self.assertTrue(frappe.db.exists("Has Role", {"parent": user, "parenttype": "User", "role": role}))

	def test_enforce_after_date_keeps_the_date(self):
		after = self._migrate(
			passkey_enrollment_policy="Enforce After Date",
			passkey_enforce_scope="All Users",
			passkey_enforce_after="2099-01-01",
		)
		self.assertEqual(after["passkey_enforce_scope"], "All users")
		self.assertEqual(after["passkey_enforce_after"], "2099-01-01")

	def test_old_off_turns_everyone_else_off(self):
		after = self._migrate(passkey_enrollment_policy="Off", passkey_enforce_scope="All Users")
		self.assertEqual(after["passkey_enforce_scope"], "No one")
		self.assertEqual(after["passkey_everyone_else"], "Off")

	def test_current_values_are_left_alone(self):
		after = self._migrate(passkey_enforce_scope="All users")
		self.assertEqual(after["passkey_enforce_scope"], "All users")

	def test_upgraded_settings_save_again(self):
		self._migrate(passkey_enrollment_policy="Nudge", passkey_enforce_scope="All Users")
		frappe.clear_cache(doctype="Passkey Settings")
		frappe.get_doc("Passkey Settings").save()
