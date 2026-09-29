# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Data patches listed in patches.txt."""

import frappe

from passkeys.patches.v15_0 import rename_first_enrollment_setting as rename_patch
from passkeys.tests.compat import IntegrationTestCase


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
