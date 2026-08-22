# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""P1 battery: install/uninstall guards, lifecycle cleanup, and exports."""

import json
import os
import stat
import types
import unittest
from unittest.mock import patch

import frappe
from frappe.utils import cint

from passkeys import install
from passkeys.patches.v17_0 import fold_nudge_flag_into_enrollment_policy as fold_nudge_patch
from passkeys.patches.v17_0 import remove_role_exemptions as remove_exemptions_patch
from passkeys.tests.compat import IntegrationTestCase, arrange_mode_floor
from passkeys.tests.factories import make_credential, make_handle, make_user


class TestVersionFloor(unittest.TestCase):
	"""Pure unit tests of the floor check against fake versions."""

	def test_below_floor_refused(self):
		# Per-major-line floors: 15.108.0 / 16.18.3 (CVE-2026-47194). 15.107.0 and the
		# 16.0.0-16.18.2 window are now refused; a single floor would have let 16.x pass.
		for version in (
			"14.99.0",
			"15.0.0",
			"15.101.0",
			"15.106.9",
			"15.106.9-beta.1",
			"15.107.0",
			"16.0.0",
			"16.18.2",
		):
			self.assertRaises(frappe.ValidationError, install.check_frappe_version, version)

	def test_at_and_above_floor_accepted(self):
		for version in ("15.108.0", "15.113.4", "16.18.3", "16.25.0", "17.0.0-dev", "18.0.0"):
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

	def test_fresh_install_refuses_partial_native_module_without_handover_marker(self):
		with (
			patch("passkeys.install.core_module_present", return_value=True),
			patch("passkeys.install.is_core_native", return_value=False),
		):
			self.assertRaises(frappe.ValidationError, install.before_install)

	def test_before_install_passes_on_this_bench(self):
		install.before_install()  # must not raise


class TestFoldNudgeMigration(unittest.TestCase):
	def _execute(self, *, current=None, legacy=None, defaults=None):
		defaults = defaults or {}

		def get_value(_doctype, filters, _field, **_kwargs):
			field = filters["field"]
			if field == "passkey_enrollment_nudge":
				return legacy
			return defaults.get(field)

		with (
			patch.object(fold_nudge_patch.install, "is_core_native", return_value=False),
			patch.object(fold_nudge_patch.frappe.db, "get_single_value", return_value=current),
			patch.object(fold_nudge_patch.frappe.db, "get_value", side_effect=get_value),
			patch.object(fold_nudge_patch.frappe.db, "set_single_value") as set_single,
			patch.object(fold_nudge_patch.frappe.db, "delete") as delete,
		):
			fold_nudge_patch.execute()
		return set_single, delete

	def test_legacy_zero_and_one_map_to_off_and_nudge(self):
		for legacy, expected in (("0", "Off"), ("1", "Nudge")):
			with self.subTest(legacy=legacy):
				set_single, _delete = self._execute(current=None, legacy=legacy)
				set_single.assert_any_call("Passkey Settings", "passkey_enrollment_policy", expected)

	def test_preselected_policy_is_never_overwritten(self):
		set_single, delete = self._execute(current="Enforce", legacy="1")
		policy_writes = [
			call for call in set_single.call_args_list if call.args[1] == "passkey_enrollment_policy"
		]
		self.assertEqual(policy_writes, [])
		delete.assert_called_once_with(
			"Singles", {"doctype": "Passkey Settings", "field": "passkey_enrollment_nudge"}
		)

	def test_rerun_with_persisted_values_is_idempotent(self):
		set_single, delete = self._execute(current="Nudge", defaults=fold_nudge_patch._ENFORCEMENT_DEFAULTS)
		set_single.assert_not_called()
		delete.assert_called_once()


class TestFoldNudgeMigrationDatabase(IntegrationTestCase):
	def test_real_legacy_singles_row_is_folded_and_removed(self):
		frappe.db.delete(
			"Singles",
			{
				"doctype": "Passkey Settings",
				"field": ["in", ["passkey_enrollment_nudge", "passkey_enrollment_policy"]],
			},
		)
		frappe.db.sql(
			"""insert into `tabSingles` (`doctype`, `field`, `value`)
			values (%s, %s, %s)""",
			("Passkey Settings", "passkey_enrollment_nudge", "1"),
		)

		with patch.object(fold_nudge_patch.install, "is_core_native", return_value=False):
			fold_nudge_patch.execute()

		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy"), "Nudge")
		self.assertFalse(
			frappe.db.exists(
				"Singles",
				{"doctype": "Passkey Settings", "field": "passkey_enrollment_nudge"},
			)
		)


class TestRemoveRoleExemptionsMigration(IntegrationTestCase):
	def test_deletes_only_obsolete_exemption_rows(self):
		obsolete = frappe.get_doc(
			{
				"doctype": "Passkey Enforcement Role",
				"parent": "Passkey Settings",
				"parenttype": "Passkey Settings",
				"parentfield": "passkey_enforce_exempt_roles",
				"role": "System Manager",
			}
		)
		obsolete.db_insert()
		selected = frappe.get_doc(
			{
				"doctype": "Passkey Enforcement Role",
				"parent": "Passkey Settings",
				"parenttype": "Passkey Settings",
				"parentfield": "passkey_enforce_roles",
				"role": "System Manager",
			}
		)
		selected.db_insert()

		with patch.object(remove_exemptions_patch.install, "is_core_native", return_value=False):
			remove_exemptions_patch.execute()

		self.assertFalse(frappe.db.exists("Passkey Enforcement Role", obsolete.name))
		self.assertTrue(frappe.db.exists("Passkey Enforcement Role", selected.name))

	def test_native_core_short_circuits(self):
		with (
			patch.object(remove_exemptions_patch.install, "is_core_native", return_value=True),
			patch.object(remove_exemptions_patch.frappe.db, "delete") as delete,
			patch.object(remove_exemptions_patch.frappe, "clear_document_cache") as clear_cache,
		):
			remove_exemptions_patch.execute()
		delete.assert_not_called()
		clear_cache.assert_not_called()


class TestCoreHandoverCapability(unittest.TestCase):
	def tearDown(self):
		install._CORE_NATIVE = None

	def test_module_presence_without_contract_does_not_make_app_dormant(self):
		install._CORE_NATIVE = None
		with (
			patch("passkeys.install.core_module_present", return_value=True),
			patch("passkeys.install.importlib.import_module", return_value=types.SimpleNamespace()),
		):
			self.assertFalse(install.is_core_native())

	def test_exact_handover_contract_makes_app_dormant(self):
		install._CORE_NATIVE = None
		module = types.SimpleNamespace(FRAPPE_PASSKEYS_APP_HANDOVER=install.CORE_HANDOVER_CAPABILITY)
		with (
			patch("passkeys.install.core_module_present", return_value=True),
			patch("passkeys.install.importlib.import_module", return_value=module),
		):
			self.assertTrue(install.is_core_native())


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
		arrange_mode_floor(self)  # mode floor for the flagged handle
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
	idempotently on reinstall while refusing identifier-matched data conflicts."""

	def setUp(self):
		super().setUp()
		arrange_mode_floor(self)  # floor for flagged handles + the flagged-handle import insert

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
		other_user = self._make_user()
		other_cred = make_credential(other_user)
		make_handle(other_user)

		path = install.export_credentials(self._export_path())
		self.assertTrue(os.path.exists(path))
		with open(path) as fh:
			data = json.load(fh)
		self.assertEqual(data["schema"], install.CREDENTIAL_EXPORT_SCHEMA)
		self.assertIn(cred.credential_id_sha256, [c["credential_id_sha256"] for c in data["credentials"]])

		# Remove only this test user's rows. A shared integration site must never
		# lose unrelated credentials merely to simulate an empty reinstall.
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})

		summary = install.import_credentials(path, allow_existing=True)
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
		self.assertTrue(frappe.db.exists("WebAuthn Credential", other_cred.name))

	def test_import_is_idempotent(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)

		path = install.export_credentials(self._export_path())
		# the rows are still present → a re-import creates nothing and skips them
		summary = install.import_credentials(path, allow_existing=True)
		self.assertEqual(summary["credentials_created"], 0)
		self.assertEqual(summary["handles_created"], 0)
		self.assertGreaterEqual(summary["credentials_skipped"], 1)
		self.assertGreaterEqual(summary["handles_skipped"], 1)

	def test_allow_existing_rejects_weaker_existing_credential(self):
		user = self._make_user()
		cred = make_credential(user, sign_count=100)
		make_handle(user)
		path = install.export_credentials(self._export_path())
		frappe.db.set_value("WebAuthn Credential", cred.name, "sign_count", 1, update_modified=False)

		summary = install.import_credentials(path, allow_existing=True)

		self.assertIn(
			f"credentials: user={user!r}: existing credential conflicts with export",
			summary["rejected"],
		)
		self.assertEqual(cint(frappe.db.get_value("WebAuthn Credential", cred.name, "sign_count")), 1)

	def test_allow_existing_rejects_cleared_passkey_only_flag(self):
		user = self._make_user()
		make_credential(user)
		handle = make_handle(user, passkey_only_login=1)
		path = install.export_credentials(self._export_path())
		frappe.db.set_value("WebAuthn User Handle", handle.name, "passkey_only_login", 0)

		summary = install.import_credentials(path, allow_existing=True)

		self.assertIn(
			f"handles: user={user!r}: existing user handle conflicts with export",
			summary["rejected"],
		)
		self.assertEqual(
			cint(frappe.db.get_value("WebAuthn User Handle", handle.name, "passkey_only_login")), 0
		)

	def test_restores_passkey_only_handle(self):
		# credentials are restored before handles, so a passkey_only_login handle
		# clears its enabled-credential floor on insert.
		user = self._make_user()
		make_credential(user, enabled=1)
		make_handle(user, passkey_only_login=1)

		path = install.export_credentials(self._export_path())
		frappe.db.delete("WebAuthn User Handle", {"user": user})
		frappe.db.delete("WebAuthn Credential", {"user": user})

		install.import_credentials(path, allow_existing=True)
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
		self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

	def test_import_rejects_a_foreign_file(self):
		path = self._export_path()
		with open(path, "w") as fh:
			fh.write('{"schema": "not-a-passkeys-export"}')
		self.assertRaises(frappe.ValidationError, install.import_credentials, path)

	def test_unsigned_legacy_export_requires_explicit_operator_opt_in(self):
		user = self._make_user()
		cred = make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())
		with open(path) as fh:
			data = json.load(fh)
		data["version"] = 1
		data.pop("signature")
		with open(path, "w") as fh:
			fh.write(frappe.as_json(data))

		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})
		with self.assertRaises(frappe.ValidationError):
			install.import_credentials(path, allow_existing=True)
		summary = install.import_credentials(path, allow_existing=True, allow_unsigned_legacy=True)
		self.assertEqual(summary["credentials_created"], 1)
		self.assertTrue(
			frappe.db.exists("WebAuthn Credential", {"credential_id_sha256": cred.credential_id_sha256})
		)

	def _dump(self, data: dict, path: str) -> None:
		data["counts"] = {
			"credentials": len(data.get("credentials", [])),
			"user_handles": len(data.get("user_handles", [])),
		}
		data["signature"] = {
			"alg": install.CREDENTIAL_EXPORT_SIGNATURE_ALG,
			"value": install._export_signature(data),
		}
		with open(path, "w") as fh:
			fh.write(frappe.as_json(data))

	def test_import_rejects_unsigned_tampering(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())
		with open(path) as fh:
			data = json.load(fh)
		data["credentials"][0]["user"] = "Administrator"
		with open(path, "w") as fh:
			fh.write(frappe.as_json(data))
		with self.assertRaises(frappe.ValidationError):
			install.import_credentials(path, allow_existing=True)

	def test_import_rejects_a_signed_export_from_another_site(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())
		with open(path) as fh:
			data = json.load(fh)
		data["site"] = "other.localhost"
		self._dump(data, path)
		with self.assertRaises(frappe.ValidationError):
			install.import_credentials(path, allow_existing=True)

	def test_import_refuses_live_data_merge_by_default(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())
		with self.assertRaises(frappe.ValidationError):
			install.import_credentials(path)

	def test_import_rejects_rows_for_a_nonexistent_user(self):
		# A crafted export cannot bind a public key to an account that does not exist.
		user = self._make_user()
		make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())

		with open(path) as fh:
			data = json.load(fh)
		ghost = f"ghost-{frappe.generate_hash(length=8)}@example.com"
		self.assertFalse(frappe.db.exists("User", ghost))
		for row in data["credentials"] + data["user_handles"]:
			row["user"] = ghost
		self._dump(data, path)
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})

		summary = install.import_credentials(path, allow_existing=True)
		self.assertEqual(summary["credentials_created"], 0)
		self.assertEqual(summary["handles_created"], 0)
		self.assertGreaterEqual(summary["credentials_rejected"], 1)
		self.assertGreaterEqual(summary["handles_rejected"], 1)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": ghost}))
		self.assertFalse(frappe.db.exists("WebAuthn User Handle", {"user": ghost}))

	def test_import_rejects_a_disabled_user(self):
		user = self._make_user()
		make_credential(user)
		make_handle(user)
		path = install.export_credentials(self._export_path())

		frappe.db.set_value("User", user, "enabled", 0)
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})

		summary = install.import_credentials(path, allow_existing=True)
		self.assertEqual(summary["credentials_created"], 0)
		self.assertGreaterEqual(summary["credentials_rejected"], 1)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": user}))

	def test_import_rejects_user_handle_substitution(self):
		# The victim already enrolled a passkey (live handle H1). A crafted export claims a
		# DIFFERENT handle for the victim plus a credential (the attacker's key) — the
		# mismatch must reject both so the key is never bound.
		victim = self._make_user()
		make_credential(victim)
		live_handle = make_handle(victim).handle
		path = install.export_credentials(self._export_path())

		with open(path) as fh:
			data = json.load(fh)
		for row in data["user_handles"]:
			row["handle"] = frappe.generate_hash(length=64)  # forged, != H1
		self._dump(data, path)
		# drop the exported credential so a rejection means nothing new is bound to victim
		frappe.db.delete("WebAuthn Credential", {"user": victim})

		summary = install.import_credentials(path, allow_existing=True)
		self.assertEqual(summary["credentials_created"], 0)
		self.assertGreaterEqual(summary["credentials_rejected"], 1)
		self.assertGreaterEqual(summary["handles_rejected"], 1)
		# the victim's live handle is untouched, and no crafted key was bound
		self.assertEqual(frappe.db.get_value("WebAuthn User Handle", {"user": victim}, "handle"), live_handle)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": victim}))

	def test_import_keeps_valid_rows_and_rejects_only_the_bad_ones(self):
		# "import the rest": a mixed file restores the legitimate user's rows while the
		# crafted rows for a nonexistent user are rejected.
		good = self._make_user()
		make_credential(good)
		make_handle(good)
		path = install.export_credentials(self._export_path())

		with open(path) as fh:
			data = json.load(fh)
		ghost = f"ghost-{frappe.generate_hash(length=8)}@example.com"
		data["credentials"].append(
			{
				**data["credentials"][0],
				"user": ghost,
				"credential_id": frappe.generate_hash(length=43),
				"credential_id_sha256": frappe.generate_hash(length=64),
			}
		)
		data["user_handles"].append(
			{**data["user_handles"][0], "user": ghost, "handle": frappe.generate_hash(length=64)}
		)
		self._dump(data, path)
		frappe.db.delete("WebAuthn Credential", {"user": good})
		frappe.db.delete("WebAuthn User Handle", {"user": good})

		summary = install.import_credentials(path, allow_existing=True)
		self.assertGreaterEqual(summary["credentials_created"], 1)
		self.assertGreaterEqual(summary["handles_created"], 1)
		self.assertGreaterEqual(summary["credentials_rejected"], 1)
		self.assertGreaterEqual(summary["handles_rejected"], 1)
		self.assertTrue(frappe.db.exists("WebAuthn Credential", {"user": good}))
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": ghost}))


class TestLegacyRegistryPropertySetterCleanup(IntegrationTestCase):
	"""An obsolete development-build customization is removed, never created."""

	def _setter_exists(self):
		return frappe.db.exists("Property Setter", install._registry_property_setter_filters())

	def tearDown(self):
		install.cleanup_legacy_registry_property_setter()
		super().tearDown()

	def test_cleanup_is_idempotent(self):
		field = frappe.get_meta("System Settings").get_field("two_factor_method")
		frappe.get_doc(
			{
				"doctype": "Property Setter",
				"doctype_or_field": "DocField",
				"doc_type": "System Settings",
				"field_name": "two_factor_method",
				"property": "options",
				"property_type": "Text",
				"value": f"{field.options}\nPasskey",
				"module": "Passkeys",
			}
		).insert(ignore_permissions=True)
		self.assertTrue(self._setter_exists())
		install.cleanup_legacy_registry_property_setter()
		install.cleanup_legacy_registry_property_setter()
		self.assertFalse(self._setter_exists())


class TestUserFormSection(IntegrationTestCase):
	"""The User-form "Passkeys" section is placed DETERMINISTICALLY via programmatic
	Custom Fields (Section Break + HTML wrapper) right after the password / security
	area — not a dashboard section appended at the end. Install adds, after_migrate
	syncs (dropped when core-native), and before_uninstall removes."""

	def tearDown(self):
		install._remove_user_form_section()
		super().tearDown()

	def _field(self, fieldname):
		return frappe.db.get_value(
			"Custom Field",
			{"dt": "User", "fieldname": fieldname},
			["fieldtype", "label", "insert_after", "collapsible"],
			as_dict=True,
		)

	def test_sync_creates_section_and_html_after_the_password_area(self):
		install.sync_user_form_section()

		section = self._field(install.USER_FORM_SECTION_FIELD)
		html = self._field(install.USER_FORM_HTML_FIELD)
		self.assertEqual(section.fieldtype, "Section Break")
		self.assertEqual(section.label, "Passkeys")
		# collapsible ⇒ the section renders collapsed by default (management one click away)
		self.assertEqual(section.collapsible, 1)
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
