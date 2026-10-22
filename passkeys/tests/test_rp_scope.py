# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Operational RP scope, provenance and usable-credential census."""

from unittest.mock import patch

import frappe

from passkeys import ceremony, policy
from passkeys.errors import CeremonyExpired
from passkeys.tests.compat import IntegrationTestCase, PinnedSiteRp
from passkeys.tests.factories import make_credential, make_user


class RpScopeTest(PinnedSiteRp, IntegrationTestCase):
	def test_operational_origins(self):
		app = "android:apk-key-hash:" + "a" * 43
		with patch.dict(frappe.conf, {"host_name": "https://outside.test", "developer_mode": 0}):
			for origins, apps, expected in (
				("", "", None),
				("https://example.com", "", "example.com"),
				("http://example.com", "", "example.com"),
				("https://outside.test", "", None),
				("https://[broken", "", None),
				("https://example.com/path", "", None),
				("", app, "example.com"),
				("", "android:apk-key-hash:bad", None),
			):
				with self.subTest(origins=origins, apps=apps):
					settings = frappe._dict(
						passkey_rp_id=" Example.COM ", passkey_origins=origins, passkey_app_origins=apps
					)
					self.assertEqual(policy.get_site_rp_id(settings), expected)

	def test_blank_rp_uses_exact_configured_host(self):
		with patch.dict(frappe.conf, {"host_name": "https://erp.example.com"}):
			self.assertEqual(policy.get_site_rp_id({}), "erp.example.com")
			self.assertTrue(policy.is_stale("example.com", policy.get_site_rp_id({})))

	def test_http_site_is_operational_without_developer_mode(self):
		settings = {"login_with_passkey": 1}
		with patch.dict(frappe.conf, {"host_name": "http://test_site:8000", "developer_mode": 0}):
			self.assertEqual(policy.get_site_rp_id(settings), "test_site")
			self.assertFalse(policy.is_stale("test_site", policy.get_site_rp_id(settings)))
			self.assertEqual(policy.valid_web_origins(settings, "test_site"), ["http://test_site:8000"])
			problem = policy.get_rp_scope_problem(settings)
			self.assertEqual((problem["status"], problem["reason"]), ("web_works", None))
			self.assertEqual(problem["working_origins"], ["http://test_site:8000"])
			with self.assertRaises(frappe.ValidationError):
				policy.validate_origins(settings, "test_site")

	def test_stale_is_independent_of_enabled(self):
		for credential, site, expected in (
			(" Example.COM ", "example.com", False),
			("", "example.com", True),
			(None, "example.com", True),
			("erp.example.com", "example.com", True),
			("example.com", None, True),
		):
			with self.subTest(credential=credential, site=site):
				self.assertEqual(policy.is_stale(credential, site), expected)
		user = make_user()
		make_credential(user, enabled=0)
		make_credential(user, rp_id="old.example.com")
		self.assertFalse(ceremony.has_usable_credential(user))
		current = make_credential(user)
		self.assertEqual(ceremony.count_usable_credentials(user), 1)
		self.assertEqual(
			[row.name for row in ceremony.usable_credentials(user, fields=("name",))], [current.name]
		)

	def test_diagnostics_distinguish_web_app_and_off(self):
		settings = frappe._dict(login_with_passkey=1, passkey_rp_id="example.com")
		with patch.dict(frappe.conf, {"host_name": "https://outside.test", "developer_mode": 0}):
			problem = policy.get_rp_scope_problem(settings)
			self.assertEqual((problem["status"], problem["reason"]), ("off", "host_outside_rp"))
			settings.passkey_app_origins = "android:apk-key-hash:" + "a" * 43
			problem = policy.get_rp_scope_problem(settings)
			self.assertEqual(problem["status"], "app_only")
			self.assertEqual(problem["working_origins"], [settings.passkey_app_origins])
			settings.passkey_origins = "https://example.com"
			self.assertEqual(policy.get_rp_scope_problem(settings)["status"], "web_works")
		with patch.dict(frappe.conf, {"host_name": "https://example.com/path", "developer_mode": 0}):
			problem = policy.get_rp_scope_problem({"login_with_passkey": 1, "passkey_rp_id": "example.com"})
			self.assertEqual((problem["status"], problem["reason"]), ("off", "no_valid_origins"))
		with patch.dict(frappe.conf, {"host_name": ""}):
			self.assertEqual(policy.get_rp_scope_problem({"login_with_passkey": 1})["reason"], "no_rp_id")
		self.assertIsNone(policy.get_rp_scope_problem({}))

	def test_insert_normalizes_and_rp_is_write_once(self):
		doc = make_credential(make_user(), rp_id=" Example.COM ")
		self.assertEqual(doc.rp_id, "example.com")
		doc.rp_id = "other.example.com"
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)
		self.assertEqual(frappe.db.get_value(doc.doctype, doc.name, "rp_id"), "example.com")

	def test_effect_check_ignores_cached_settings_and_refuses_legacy(self):
		ceremony.require_current_rp({"rp_id": "example.com"}, error=CeremonyExpired)
		frappe.get_cached_doc("Passkey Settings")
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "changed.example.com")
		for record in ({}, {"rp_id": None}, {"rp_id": "example.com"}):
			with self.subTest(record=record), self.assertRaises(CeremonyExpired):
				ceremony.require_current_rp(record, error=CeremonyExpired)
