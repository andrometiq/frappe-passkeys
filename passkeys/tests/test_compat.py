# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Exercise committed-state cleanup through unittest's actual class lifecycle."""

import unittest
from unittest.mock import patch

import frappe

from passkeys.tests import committed_state
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class CommittedSettingsTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.baseline = committed_state.capture()
		self.addCleanup(committed_state.restore, self.baseline, self.id())

	def run_classes(self, *classes, errors=0):
		result = unittest.TestResult()
		unittest.TestSuite(cls("runTest") for cls in classes).run(result)
		self.assertEqual(len(result.errors), errors, result.errors)
		self.assertFalse(result.failures, result.failures)
		frappe.db.rollback()
		self.assertEqual(committed_state.capture(), self.baseline)
		return result

	def test_committed_fixtures_and_unrelated_pending_write(self):
		pending = "passkey-uncommitted-regression"
		created = []

		def clean_pending():
			frappe.db.rollback()
			frappe.db.delete("DefaultValue", {"parent": pending})
			frappe.db.commit()

		self.addCleanup(clean_pending)

		class Fixture(IntegrationTestCase):
			def runTest(self):
				user = make_user()
				created.append(user)
				make_credential(user)
				make_handle(user)
				for parent in ("__passkeys", "__2fa"):
					frappe.get_doc({"doctype": "DefaultValue", "parent": parent, "defkey": user}).db_insert()
				frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "changed.example")
				frappe.db.commit()
				frappe.get_doc({"doctype": "DefaultValue", "parent": pending, "defkey": pending}).db_insert()

		self.run_classes(Fixture)
		self.assertFalse(frappe.db.exists("DefaultValue", {"parent": pending}))
		self.assertFalse(frappe.db.exists("Deleted Document", {"deleted_name": ["in", created]}))

	def test_actual_system_settings_save_and_successive_classes(self):
		original = frappe.get_system_settings("language")
		baseline = self.baseline

		class Writer(IntegrationTestCase):
			def runTest(self):
				settings = frappe.get_doc("System Settings")
				settings.language = "fr" if original != "fr" else "en"
				settings.time_zone = "UTC"
				settings.save(ignore_permissions=True)
				frappe.db.commit()
				frappe.clear_cache()
				self.assertEqual(frappe.get_system_settings("language"), settings.language)

		class Reader(IntegrationTestCase):
			def runTest(self):
				self.assertEqual(frappe.get_system_settings("language"), original)
				self.assertEqual(committed_state.capture(), baseline)

		self.run_classes(Writer, Reader)
		self.assertEqual(frappe.get_system_settings("language"), original)

	def test_raw_absent_empty_null_and_children(self):
		frappe.db.delete("Singles", {"doctype": "Passkey Settings"})
		committed_state.restore_rows(
			"Singles",
			{"doctype": "Passkey Settings"},
			[
				{"doctype": "Passkey Settings", "field": "passkey_rp_id", "value": ""},
				{"doctype": "Passkey Settings", "field": "passkey_origins", "value": None},
			],
		)
		frappe.get_doc(
			{
				"doctype": "Passkey Enforcement Role",
				"parent": "Passkey Settings",
				"parenttype": "Passkey Settings",
				"parentfield": "passkey_enforce_roles",
				"role": "System Manager",
				"idx": 7,
			}
		).db_insert()
		frappe.db.commit()
		self.baseline = committed_state.capture()

		class Fixture(IntegrationTestCase):
			def runTest(self):
				frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
				frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "changed.example")
				frappe.db.delete("Passkey Enforcement Role", {"parent": "Passkey Settings"})
				frappe.db.commit()

		self.run_classes(Fixture)

	def test_failures_do_not_skip_finalizer(self):
		for stage in ("setUpClass", "setUp", "tearDown", "tearDownClass", "cleanup", "class_cleanup"):
			with self.subTest(stage=stage):

				def fail():
					raise RuntimeError("intentional lifecycle failure")

				class Fixture(IntegrationTestCase):
					@classmethod
					def setUpClass(cls):
						super().setUpClass()
						frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "changed.example")
						frappe.db.commit()
						if stage == "class_cleanup":
							cls.addClassCleanup(fail)
						if stage == "setUpClass":
							fail()

					def setUp(self):
						super().setUp()
						if stage == "cleanup":
							self.addCleanup(fail)
						if stage == "setUp":
							fail()

					def runTest(self):
						pass

					def tearDown(self):
						super().tearDown()
						if stage == "tearDown":
							fail()

					@classmethod
					def tearDownClass(cls):
						super().tearDownClass()
						if stage == "tearDownClass":
							fail()

				self.run_classes(Fixture, errors=1)

	def test_finalizer_error_surfaces_and_clears_cache(self):
		class Fixture(IntegrationTestCase):
			def runTest(self):
				frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "changed.example")
				frappe.db.commit()

		with patch.object(committed_state, "restore_rows", side_effect=RuntimeError("restore failed")):
			with patch.object(frappe, "clear_cache", wraps=frappe.clear_cache) as clear:
				result = unittest.TestResult()
				unittest.TestSuite([Fixture("runTest")]).run(result)
				self.assertEqual(len(result.errors), 1, result.errors)
				self.assertIn("restore failed", result.errors[0][1])
				clear.assert_called()
