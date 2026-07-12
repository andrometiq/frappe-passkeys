# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""P1 battery: install/uninstall guards — the version floor,
the fresh-install-onto-native-core refusal, the uninstall lockout guards and
cleanup, and the registry Property Setter lifecycle."""

import json
import os
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


class TestNavbarCleanup(IntegrationTestCase):
	"""E1: "My Passkeys" moved from the avatar menu into the User-form "Passkeys"
	section, so the app no longer declares a standard_navbar_items hook and
	after_migrate cleans up the previously-synced item on existing sites."""

	def tearDown(self):
		install._remove_navbar_item()
		super().tearDown()

	def _add_legacy_item(self):
		navbar = frappe.get_doc("Navbar Settings")
		navbar.append(
			"settings_dropdown",
			{
				"item_label": "My Passkeys",
				"item_type": "Action",
				"action": install.NAVBAR_ITEM_ACTION,
				"is_standard": 1,
			},
		)
		navbar.save(ignore_permissions=True)

	def _item_exists(self):
		return frappe.db.exists(
			"Navbar Item", {"parent": "Navbar Settings", "action": install.NAVBAR_ITEM_ACTION}
		)

	def test_app_no_longer_advertises_the_navbar_item(self):
		items = frappe.get_hooks("standard_navbar_items") or []
		labels = [it.get("item_label") for it in items if isinstance(it, dict)]
		self.assertNotIn("My Passkeys", labels)

	def test_after_migrate_removes_a_previously_synced_item(self):
		self._add_legacy_item()
		self.assertTrue(self._item_exists())
		install.sync_standard_navbar_items()
		self.assertFalse(self._item_exists())

	def test_removal_is_idempotent_when_absent(self):
		self.assertFalse(self._item_exists())
		install.sync_standard_navbar_items()  # must not raise
		self.assertFalse(self._item_exists())


class TestCredentialExportImport(IntegrationTestCase):
	"""L1: an uninstall exports the credential tables (which it is about to drop) so
	removal is non-destructive, and a documented console helper restores them
	idempotently on reinstall — keyed on ``credential_id_sha256``."""

	def _make_user(self) -> str:
		user = make_user()
		# Restored rows (import_credentials inserts) are not tracked by the User
		# force-delete cascade, so purge the WebAuthn rows explicitly — a leaked
		# passkey_only_login=1 handle would poison the uninstall-lockout guards.
		self.addCleanup(self._purge_user, user)
		return user

	def _purge_user(self, user: str) -> None:
		# import_credentials commits, so the restored rows escape the harness rollback;
		# commit the row deletion too, then best-effort delete the User (which can raise
		# on its links) — the passkey_only_login=1 handle is what must never survive.
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})
		frappe.db.commit()
		try:
			frappe.delete_doc("User", user, force=1, ignore_permissions=True)
			frappe.db.commit()
		except Exception:
			frappe.db.rollback()

	def _export_path(self) -> str:
		path = frappe.get_site_path(
			"private", "files", f"passkeys-export-test-{frappe.generate_hash(length=8)}.json"
		)
		self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
		return path

	def test_export_import_round_trip(self):
		user = self._make_user()
		cred = make_credential(user, sign_count=7, label="Yubikey 5")
		make_handle(user)

		path = install.export_credentials(self._export_path())
		self.assertTrue(os.path.exists(path))
		with open(path) as fh:
			data = json.load(fh)
		self.assertEqual(data["schema"], install.CREDENTIAL_EXPORT_SCHEMA)
		self.assertIn(cred.credential_id_sha256, [c["credential_id_sha256"] for c in data["credentials"]])

		# drop the rows (simulate the uninstall-then-reinstall gap), then restore
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})

		summary = install.import_credentials(path)
		self.assertGreaterEqual(summary["credentials_created"], 1)
		self.assertGreaterEqual(summary["handles_created"], 1)
		restored = frappe.db.get_value(
			"WebAuthn Credential",
			{"credential_id_sha256": cred.credential_id_sha256},
			["sign_count", "label"],
			as_dict=True,
		)
		self.assertEqual(cint(restored.sign_count), 7)  # the counter is restored, never reset
		self.assertEqual(restored.label, "Yubikey 5")

	def test_import_is_idempotent(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)

		path = install.export_credentials(self._export_path())
		# the rows are still present → a re-import creates nothing and skips them
		summary = install.import_credentials(path)
		self.assertEqual(summary["credentials_created"], 0)
		self.assertEqual(summary["handles_created"], 0)
		self.assertGreaterEqual(summary["credentials_skipped"], 1)
		self.assertGreaterEqual(summary["handles_skipped"], 1)

	def test_restores_passkey_only_handle(self):
		# credentials are restored before handles, so a passkey_only_login handle
		# clears its enabled-credential floor on insert.
		user = self._make_user()
		make_credential(user, enabled=1)
		make_handle(user, passkey_only_login=1)

		path = install.export_credentials(self._export_path())
		frappe.db.delete("WebAuthn User Handle", {"user": user})
		frappe.db.delete("WebAuthn Credential", {"user": user})

		install.import_credentials(path)
		self.assertEqual(
			cint(frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login")), 1
		)

	def test_default_path_lands_in_private_files(self):
		user = self._make_user()
		make_credential(user)

		path = install.export_credentials()
		self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
		self.assertIn(os.path.join("private", "files"), path)
		self.assertTrue(path.endswith(".json"))

	def test_import_rejects_a_foreign_file(self):
		path = self._export_path()
		with open(path, "w") as fh:
			fh.write('{"schema": "not-a-passkeys-export"}')
		self.assertRaises(frappe.ValidationError, install.import_credentials, path)


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


class TestUserFormSection(IntegrationTestCase):
	"""The User-form "Passkeys" section is placed DETERMINISTICALLY via programmatic
	Custom Fields (Section Break + HTML wrapper) right after the password / security
	area — not a dashboard section appended at the end. Lifecycle mirrors the registry
	Property Setter: install adds, after_migrate syncs (dropped when core-native),
	before_uninstall removes."""

	def tearDown(self):
		install._remove_user_form_section()
		super().tearDown()

	def _field(self, fieldname):
		return frappe.db.get_value(
			"Custom Field",
			{"dt": "User", "fieldname": fieldname},
			["fieldtype", "label", "insert_after"],
			as_dict=True,
		)

	def test_sync_creates_section_and_html_after_the_password_area(self):
		install.sync_user_form_section()

		section = self._field(install.USER_FORM_SECTION_FIELD)
		html = self._field(install.USER_FORM_HTML_FIELD)
		self.assertEqual(section.fieldtype, "Section Break")
		self.assertEqual(section.label, "Passkeys")
		self.assertEqual(html.fieldtype, "HTML")
		# the HTML wrapper sits inside the Passkeys section
		self.assertEqual(html.insert_after, install.USER_FORM_SECTION_FIELD)
		# the section anchors on a REAL field of the User security/password area
		self.assertIn(section.insert_after, install._USER_FORM_ANCHOR_CANDIDATES)
		self.assertTrue(frappe.get_meta("User").has_field(section.insert_after))

	def test_anchor_is_the_change_password_area_tail(self):
		# on v15/v16/develop the primary anchor (redirect_url — the last field of the
		# "Change Password" section) is present, so the section lands right after it.
		self.assertEqual(install._user_form_anchor(), "redirect_url")

	def test_sync_is_idempotent(self):
		install.sync_user_form_section()
		install.sync_user_form_section()  # must not raise / duplicate
		self.assertTrue(self._field(install.USER_FORM_SECTION_FIELD))
		self.assertTrue(self._field(install.USER_FORM_HTML_FIELD))
		self.assertEqual(
			frappe.db.count("Custom Field", {"dt": "User", "fieldname": install.USER_FORM_HTML_FIELD}), 1
		)

	def test_sync_removes_the_section_when_core_native(self):
		install.sync_user_form_section()
		self.assertTrue(self._field(install.USER_FORM_SECTION_FIELD))

		with patch("passkeys.install.is_core_native", return_value=True):
			install.sync_user_form_section()
		self.assertFalse(self._field(install.USER_FORM_SECTION_FIELD))
		self.assertFalse(self._field(install.USER_FORM_HTML_FIELD))

	def test_removal_is_explicit_and_idempotent(self):
		install.sync_user_form_section()
		self.assertTrue(self._field(install.USER_FORM_HTML_FIELD))

		install._remove_user_form_section()  # the before_uninstall step
		self.assertFalse(self._field(install.USER_FORM_SECTION_FIELD))
		self.assertFalse(self._field(install.USER_FORM_HTML_FIELD))
		install._remove_user_form_section()  # idempotent, must not raise
