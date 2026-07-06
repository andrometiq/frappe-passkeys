# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Desk boot flag (DESIGN-v1 §8.1) + the Signal-API data endpoint (§8.3):
``extend_bootinfo`` publishes the reconciled P6 boot contract (``enabled``,
``modes``, ``credential_count``, ``nudge_state``, ``post_login_method``,
``conditional_create``, ``upsell_eligible``, ``settings_context``, ``rp_id`` —
build-p6-frontend-manifest.md §3) for an authed user, no-ops for Guest, and
``get_signal_data`` returns the caller's own handle + enabled credential ids."""

import frappe

from passkeys import boot, passkey, state
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user

RP_ID = "example.com"


class BootInfoTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enrollment_nudge = 1
		settings.passkey_nudge_max_prompts = 3
		settings.passkey_nudge_cooldown_days = 30
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		for field in (
			"passkey_rp_id",
			"passkey_origins",
			"login_with_passkey",
			"passkey_as_second_factor",
			"passkey_enrollment_nudge",
			"passkey_nudge_max_prompts",
			"passkey_nudge_cooldown_days",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"}
		)
		return user

	# ---- extend_bootinfo shape (§8.1) -------------------------------------

	def test_bootinfo_shape_for_authed_user(self):
		user = self._user()
		make_credential(user, label="k")
		frappe.set_user(user)
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
				"nudge_state",
				"post_login_method",
				"conditional_create",
				"upsell_eligible",
				"settings_context",
				"rp_id",
			},
		)
		self.assertTrue(pk["enabled"])  # login_with_passkey on ⇒ any-mode gate true
		self.assertTrue(pk["modes"]["first_factor"])
		self.assertFalse(pk["modes"]["second_factor"])
		self.assertEqual(pk["credential_count"], 1)
		self.assertEqual(pk["rp_id"], RP_ID)
		# credential_count > 0 ⇒ nudge not eligible
		self.assertFalse(pk["nudge_state"]["eligible"])

	def test_bootinfo_nudge_eligible_when_zero_credentials(self):
		user = self._user()
		frappe.set_user(user)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertEqual(info.passkeys["credential_count"], 0)
		self.assertTrue(info.passkeys["nudge_state"]["eligible"])

	def test_bootinfo_is_a_noop_for_guest(self):
		frappe.set_user("Guest")
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertIsNone(info.get("passkeys"))

	def test_post_login_method_reflects_the_sudo_window(self):
		user = self._user()
		frappe.set_user(user)
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		self.assertEqual(info.passkeys["post_login_method"], "password")

	# ---- get_signal_data (§8.3) -------------------------------------------

	def test_get_signal_data_returns_own_handle_and_enabled_creds(self):
		user = self._user()
		make_handle(user)
		cred = make_credential(user)
		make_credential(user, enabled=0)  # disabled — excluded from the signal
		frappe.set_user(user)
		data = passkey.get_signal_data()
		self.assertEqual(data["rp_id"], RP_ID)
		self.assertTrue(data["user_handle"])
		self.assertEqual(data["credential_ids"], [cred.credential_id])

	def test_get_signal_data_requires_auth(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.AuthenticationError):
			passkey.get_signal_data()
