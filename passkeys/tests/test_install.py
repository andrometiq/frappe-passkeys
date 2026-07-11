# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""P1 battery: install/uninstall guards — the version floor,
the fresh-install-onto-native-core refusal, the uninstall lockout guards and
cleanup, and the registry Property Setter lifecycle."""

import unittest
from unittest.mock import patch

import frappe
from frappe.utils import cint

from passkeys import install
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class TestVersionFloor(unittest.TestCase):
	"""Pure unit tests of the floor check against fake versions."""

	def test_below_floor_refused(self):
		for version in ("14.99.0", "15.0.0", "15.101.0", "15.106.9", "15.106.9-beta.1"):
			self.assertRaises(frappe.ValidationError, install.check_frappe_version, version)

	def test_at_and_above_floor_accepted(self):
		for version in ("15.107.0", "15.113.4", "16.0.0", "16.25.0", "17.0.0-dev", "18.0.0"):
			install.check_frappe_version(version)  # must not raise

	def test_version_tuple_parsing(self):
		self.assertEqual(install._version_tuple("15.107.0"), (15, 107, 0))
		self.assertEqual(install._version_tuple("17.0.0-dev"), (17, 0, 0))
		self.assertEqual(install._version_tuple("16.25.0+custom"), (16, 25, 0))
		self.assertEqual(install._version_tuple("16"), (16, 0, 0))


class TestInstallGuards(IntegrationTestCase):
	def test_running_frappe_satisfies_floor(self):
		install.check_frappe_version()  # must not raise on a supported bench

	def test_fresh_install_onto_native_core_is_refused(self):
		with patch("passkeys.install.is_core_native", return_value=True):
			self.assertRaises(frappe.ValidationError, install.before_install)

	def test_before_install_passes_on_this_bench(self):
		install.before_install()  # must not raise


class TestUninstallGuards(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._disable_user_pass_login = cint(
			frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		)
		self._login_with_email_link = cint(
			frappe.db.get_single_value("System Settings", "login_with_email_link")
		)

	def tearDown(self):
		self._set_ss("disable_user_pass_login", self._disable_user_pass_login)
		self._set_ss("login_with_email_link", self._login_with_email_link)
		super().tearDown()

	def _set_ss(self, field, value):
		"""Toggle a System Settings login field AND bust both caches. Anything that
		reads ``frappe.get_system_settings`` while a toggle is live caches the whole
		singles dict on ``frappe.local.system_settings``; the runner's thread-local
		restore does NOT clear that attribute, so a stale ``disable_user_pass_login=1``
		would leak into later modules and trip ``_guard_last_login_method`` there
		(mirrors ``test_management_p6._set_disable`` / ``test_second_factor._set_system_2fa``)."""
		frappe.db.set_single_value("System Settings", field, value)
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None  # bust the request-local singles cache

	def _make_user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def test_blocks_while_any_user_is_passkey_only(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)

		with self.assertRaises(frappe.ValidationError) as ctx:
			install.before_uninstall()
		self.assertIn(user, str(ctx.exception))

		frappe.db.set_value("WebAuthn User Handle", {"user": user}, "passkey_only_login", 0)
		install.before_uninstall()  # must not raise

	def test_blocks_when_no_login_method_would_survive(self):
		self._set_ss("disable_user_pass_login", 1)
		self._set_ss("login_with_email_link", 0)
		if frappe.db.exists("Social Login Key", {"enable_social_login": 1}) or cint(
			frappe.db.get_single_value("LDAP Settings", "enabled")
		):
			self.skipTest("another login method is configured on this site")

		self.assertRaises(frappe.ValidationError, install.before_uninstall)

		self._set_ss("login_with_email_link", 1)
		install.before_uninstall()  # must not raise

	def test_uninstall_deletes_passkeys_default_rows(self):
		frappe.db.set_default("someone_passkey_nudge", '{"declines": 1}', parent=install.DEFAULTS_PARENT)
		self.assertTrue(frappe.db.exists("DefaultValue", {"parent": install.DEFAULTS_PARENT}))

		install.before_uninstall()

		self.assertFalse(frappe.db.exists("DefaultValue", {"parent": install.DEFAULTS_PARENT}))


class TestRegistryPropertySetter(IntegrationTestCase):
	"""Programmatic, module-tagged, guard-keyed — never a fixtures/ fixture."""

	def _setter_exists(self):
		return frappe.db.exists("Property Setter", install._registry_property_setter_filters())

	def tearDown(self):
		install._remove_registry_property_setter()
		super().tearDown()

	def test_absent_by_default(self):
		# no released branch has the Stage-1 registry symbol
		self.assertFalse(install.two_factor_registry_available())
		install.sync_registry_fixture()
		self.assertFalse(self._setter_exists())

	def test_created_when_registry_present_and_removed_when_gone(self):
		with patch("passkeys.install.two_factor_registry_available", return_value=True):
			install.sync_registry_fixture()

		name = self._setter_exists()
		self.assertTrue(name)
		row = frappe.db.get_value("Property Setter", name, ["value", "module"], as_dict=True)
		self.assertIn("Passkey", row.value.split("\n"))
		self.assertEqual(row.module, "Passkeys")

		# guard false again (downgrade/revert) → removed
		install.sync_registry_fixture()
		self.assertFalse(self._setter_exists())

	def test_never_created_when_core_native(self):
		with (
			patch("passkeys.install.two_factor_registry_available", return_value=True),
			patch("passkeys.install.is_core_native", return_value=True),
		):
			install.sync_registry_fixture()
		self.assertFalse(self._setter_exists())
