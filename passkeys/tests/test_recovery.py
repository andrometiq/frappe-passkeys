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
		self._policy = frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy")
		self._grace = frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins")
		self.addCleanup(self._restore)
		frappe.db.set_single_value("Passkey Settings", "passkey_enrollment_policy", "Enforce")
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_grace_logins", 7)
		flush_settings_cache()

	def _restore(self):
		frappe.db.set_single_value("Passkey Settings", "passkey_enrollment_policy", self._policy)
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_grace_logins", self._grace)
		flush_settings_cache()
		frappe.db.commit()

	def test_drops_to_nudge_is_idempotent_and_preserves_other_settings(self):
		output = StringIO()
		with redirect_stdout(output):
			self.assertEqual(recovery.disable_enforcement(), "Nudge")
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy"), "Nudge")
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins"), 7)
		self.assertIn("changed from Enforce to Nudge", output.getvalue())

		output = StringIO()
		with redirect_stdout(output):
			self.assertEqual(recovery.disable_enforcement(), "Nudge")
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy"), "Nudge")
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins"), 7)
		self.assertIn("already disabled", output.getvalue())
