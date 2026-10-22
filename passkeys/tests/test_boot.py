# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Desk boot flag + the Signal-API data endpoint:
``extend_bootinfo`` publishes the reconciled boot contract (``enabled``,
``modes``, ``credential_count``, ``nudge_state``, ``post_login_method``, ``impersonated``,
``conditional_create``, ``upsell_eligible``, ``rp_id``) for an authed user, no-ops for Guest, and
``get_signal_data`` returns the caller's own handle + enabled credential ids."""

import os
from unittest.mock import patch

import frappe

from passkeys import boot, passkey, state
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.committed_state import delete_fixture
from passkeys.tests.compat import IntegrationTestCase, PinnedSiteRp, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user, sign_in

RP_ID = "example.com"


class BootInfoTest(PinnedSiteRp, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = "https://example.com"
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enforce_scope = "No one"
		settings.passkey_enforce_privileged_always = 0
		settings.passkey_everyone_else = "Nudge"
		settings.passkey_nudge_max_prompts = 3
		settings.passkey_nudge_cooldown_days = 30
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		sign_in("Administrator")
		for field in (
			"passkey_rp_id",
			"passkey_origins",
			"login_with_passkey",
			"passkey_as_second_factor",
			"passkey_enforce_scope",
			"passkey_enforce_privileged_always",
			"passkey_everyone_else",
			"passkey_nudge_max_prompts",
			"passkey_nudge_cooldown_days",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		flush_settings_cache()

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(
			delete_fixture, "User", user, force=1, ignore_permissions=True, delete_permanently=True
		)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"}
		)
		return user

	# ---- extend_bootinfo shape -------------------------------------

	def test_bootinfo_shape_for_authed_user(self):
		user = self._user()
		make_credential(user, label="k")
		sign_in(user)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		pk = info.get("passkeys")
		self.assertIsNotNone(pk)
		self.assertEqual(
			set(pk),
			{
				"enabled",
				"modes",
				"credential_count",
				"passkey_only_login",
				"nudge_state",
				"post_login_method",
				"impersonated",
				"conditional_create",
				"upsell_eligible",
				"enforcement",
				"rp_id",
			},
		)
		self.assertTrue(pk["enabled"])  # login_with_passkey on ⇒ any-mode gate true
		self.assertTrue(pk["modes"]["first_factor"])
		self.assertFalse(pk["modes"]["second_factor"])
		self.assertEqual(pk["credential_count"], 1)
		self.assertEqual(pk["rp_id"], RP_ID)
		self.assertEqual(pk["passkey_only_login"], 0)  # no handle row ⇒ 0
		# credential_count > 0 ⇒ nudge not eligible
		self.assertFalse(pk["nudge_state"]["eligible"])

	def test_bootinfo_passkey_only_login_reflects_the_handle_flag(self):
		"""C2-payload-exposure (boot): the toggle reads passkey_only_login from the
		boot payload — it must ship the caller's actual handle-row flag."""
		user = self._user()
		make_credential(user, label="k")
		make_handle(user, passkey_only_login=1)
		sign_in(user)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertEqual(info.passkeys["passkey_only_login"], 1)

	def test_bootinfo_nudge_eligible_when_zero_credentials(self):
		user = self._user()
		sign_in(user)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertEqual(info.passkeys["credential_count"], 0)
		self.assertTrue(info.passkeys["nudge_state"]["eligible"])

	def test_bootinfo_flags_an_impersonated_session(self):
		user = self._user()
		sign_in(user)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertIs(info.passkeys["impersonated"], False)

		frappe.session.data.impersonated_by = "Administrator"
		self.addCleanup(frappe.session.data.pop, "impersonated_by", None)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertIs(info.passkeys["impersonated"], True)

	def test_bootinfo_is_a_noop_for_guest(self):
		frappe.set_user("Guest")
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertIsNone(info.get("passkeys"))

	def test_system_manager_boot_never_scans_users(self):
		user = self._user()
		frappe.get_doc("User", user).add_roles("System Manager")
		sign_in(user)
		frappe.get_roles(user)  # warm this user's role cache
		info = frappe._dict()
		with (
			patch.object(boot, "refresh_enforcement_preview") as preview,
			patch.object(frappe, "get_all", wraps=frappe.get_all) as get_all,
		):
			boot.extend_bootinfo(info)
		preview.assert_not_called()
		self.assertIsNotNone(info.get("passkeys"))
		self.assertNotIn("settings_context", info.passkeys)
		self.assertFalse(any(call.args and call.args[0] == "User" for call in get_all.call_args_list))

	def test_post_login_method_reflects_the_sudo_window(self):
		user = self._user()
		sign_in(user)
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertEqual(info.passkeys["post_login_method"], "password")

	# ---- get_signal_data -------------------------------------------

	def test_get_signal_data_returns_own_handle_and_enabled_creds(self):
		user = self._user()
		make_handle(user)
		cred = make_credential(user)
		make_credential(user, enabled=0)  # disabled — excluded from the signal
		sign_in(user)
		data = passkey.get_signal_data()
		self.assertEqual(data["rp_id"], RP_ID)
		self.assertTrue(data["user_handle"])
		self.assertEqual(data["credential_ids"], [cred.credential_id])

	def test_get_signal_data_includes_name_and_display_name_for_current_user_details(self):
		# F2: signalCurrentUserDetails feed — name mirrors the WebAuthn userName (login id),
		# display_name the userDisplayName (full_name), so the provider's label stays in sync.
		user = self._user()
		make_handle(user)
		frappe.db.set_value("User", user, "full_name", "Ada Lovelace")
		sign_in(user)
		data = passkey.get_signal_data()
		self.assertEqual(data["name"], user)
		self.assertEqual(data["display_name"], "Ada Lovelace")

	def test_get_signal_data_requires_auth(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.AuthenticationError):
			passkey.get_signal_data()

	def test_both_modes_off_disable_nudge_and_upsell(self):
		user = self._user()
		for first, second in ((0, 0), (1, 0), (0, 1)):
			with self.subTest(first=first, second=second):
				frappe.db.set_single_value("Passkey Settings", "login_with_passkey", first)
				frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", second)
				flush_settings_cache()
				payload = boot.build_passkeys_boot(user)
				self.assertEqual(payload["nudge_state"]["eligible"], bool(first or second))
				self.assertEqual(payload["upsell_eligible"], bool(first or second))

	def test_boot_and_signals_count_only_current_enabled_rows(self):
		from passkeys import policy

		user = self._user()
		current = make_credential(user)
		make_credential(user, rp_id="old.example.com")
		make_credential(user, enabled=0)
		sign_in(user)
		self.assertEqual(boot.build_passkeys_boot(user)["credential_count"], 1)
		with patch.object(policy, "get_site_rp_id", wraps=policy.get_site_rp_id) as resolve:
			data = passkey.get_signal_data()
		self.assertEqual(resolve.call_count, 1)
		self.assertEqual(data["credential_ids"], [current.credential_id])
		self.assertEqual(data["rp_id"], RP_ID)
		original = frappe.db.get_single_value("Passkey Settings", "passkey_app_origins")
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", "passkey_app_origins", original)
		frappe.db.set_single_value("Passkey Settings", "passkey_app_origins", "")
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "outside.test")
		flush_settings_cache()
		with patch.dict(frappe.conf, {"host_name": "https://example.com"}):
			self.assertIsNone(passkey.get_signal_data())


class AppsScreenEntryTest(IntegrationTestCase):
	def test_logo_reaches_the_about_dialog_but_no_tile_shows(self):
		from frappe.utils.change_log import get_versions

		entry = frappe.get_hooks("add_to_apps_screen", app_name="passkeys")[0]
		logo = entry["logo"]
		self.assertTrue(os.path.isfile(frappe.get_app_path("passkeys", "public", *logo.split("/")[3:])))
		self.assertFalse(frappe.get_attr(entry["has_permission"])())
		self.assertFalse(frappe.get_hooks("app_logo_url", app_name="passkeys"))
		versions = get_versions()["passkeys"]
		if "logo" in versions:  # v16+ About dialog
			self.assertEqual(versions["logo"], logo)
