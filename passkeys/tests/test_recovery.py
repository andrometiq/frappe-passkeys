# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Console-only enrollment-enforcement recovery."""

from contextlib import redirect_stdout
from io import StringIO

import frappe

from passkeys import recovery
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache


class DisableEnforcementRecoveryTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._scope = frappe.db.get_single_value("Passkey Settings", "passkey_enforce_scope")
		self._privileged = frappe.db.get_single_value("Passkey Settings", "passkey_enforce_privileged_always")
		self._everyone_else = frappe.db.get_single_value("Passkey Settings", "passkey_everyone_else")
		self._grace = frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins")
		self.addCleanup(self._restore)
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_scope", "All users")
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_privileged_always", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_everyone_else", "Off")
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_grace_logins", 7)
		flush_settings_cache()

	def _restore(self):
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_scope", self._scope)
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_privileged_always", self._privileged)
		frappe.db.set_single_value("Passkey Settings", "passkey_everyone_else", self._everyone_else)
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_grace_logins", self._grace)
		flush_settings_cache()
		frappe.db.commit()

	def test_clears_scope_and_privileged_and_preserves_other_settings(self):
		output = StringIO()
		with redirect_stdout(output):
			self.assertIsNone(recovery.disable_enforcement())
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_scope"), "No one")
		self.assertEqual(
			frappe.db.get_single_value("Passkey Settings", "passkey_enforce_privileged_always"), 0
		)
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_everyone_else"), "Off")
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins"), 7)
		printed = output.getvalue()
		self.assertIn("No one", printed)
		self.assertIn("System Managers", printed)

		output = StringIO()
		with redirect_stdout(output):
			self.assertIsNone(recovery.disable_enforcement())
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_scope"), "No one")
		self.assertEqual(
			frappe.db.get_single_value("Passkey Settings", "passkey_enforce_privileged_always"), 0
		)
		self.assertIn("already disabled", output.getvalue())
