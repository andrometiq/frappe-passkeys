"""RP impact previews and guarded stale-passkey removal."""

from unittest.mock import patch

import frappe

from passkeys import policy, rp_admin, state
from passkeys.errors import ImpersonatedSessionRefused
from passkeys.passkeys.doctype.passkey_settings.passkey_settings import (
	get_resolved_rp_id,
	get_rp_id_change_impact,
	get_settings_context,
	remove_stale_passkeys,
)
from passkeys.tests.committed_state import delete_fixture
from passkeys.tests.compat import IntegrationTestCase, PinnedSiteRp, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user, sign_in


class RpAdminTest(PinnedSiteRp, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		sign_in("Administrator")
		self.addCleanup(sign_in, "Administrator")
		self.addCleanup(flush_settings_cache)
		self.addCleanup(setattr, frappe.conf, "host_name", frappe.conf.get("host_name"))
		frappe.conf.host_name = "https://example.com"
		self.snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", self.snapshot)
		frappe.db.set_single_value(
			"Passkey Settings",
			{
				"login_with_passkey": 1,
				"passkey_as_second_factor": 0,
				"passkey_app_origins": "",
				"passkey_notify_on_change": 1,
			},
		)
		flush_settings_cache()
		for endpoint in (
			"get_rp_id_change_impact",
			"remove_stale_passkeys",
			"get_settings_context",
			"get_resolved_rp_id",
		):
			key = f"{state.RATE_LIMIT_PREFIX}{endpoint}:Administrator"
			state.clear_counter(key)
			self.addCleanup(state.clear_counter, key)
		self.user = self.user_fixture()
		make_handle(self.user)

	def tearDown(self):
		sign_in("Administrator")
		super().tearDown()

	def user_fixture(self):
		user = make_user()
		self.addCleanup(
			delete_fixture, "User", user, force=1, ignore_permissions=True, delete_permanently=True
		)
		return user

	def test_impact_counts_distinct_users_and_only_working_transitions(self):
		make_credential(self.user)
		make_credential(self.user)
		make_credential(self.user, rp_id="other.example", enabled=0)
		make_credential(self.user, rp_id="other.example")
		make_credential(self.user_fixture(), rp_id="other.example")
		out = get_rp_id_change_impact(" OTHER.EXAMPLE ", "https://other.example")
		self.assertEqual(
			out,
			{
				"current_rp_id": "example.com",
				"new_rp_id": "other.example",
				"new_off": False,
				"stop": {"passkeys": 2, "users": 1},
				"start": {"passkeys": 2, "users": 2},
			},
		)
		self.assertEqual(policy.get_site_rp_id(), "example.com")

	def test_blank_parent_off_and_unchanged_candidates(self):
		make_credential(self.user)
		make_credential(self.user, rp_id="com")
		for candidate in ("", "EXAMPLE.COM"):
			out = get_rp_id_change_impact(candidate)
			self.assertEqual(out["new_rp_id"], "example.com")
			self.assertEqual(out["stop"]["passkeys"], 0)
			self.assertEqual(out["start"]["passkeys"], 0)
		out = get_rp_id_change_impact("com")
		self.assertEqual(out["stop"], {"passkeys": 1, "users": 1})
		self.assertEqual(out["start"], {"passkeys": 1, "users": 1})
		out = get_rp_id_change_impact("other.example", "", "")
		self.assertTrue(out["new_off"])
		self.assertIsNone(out["new_rp_id"])
		self.assertEqual(out["stop"]["passkeys"], 1)

	def test_invalid_candidate_is_distinct_from_valid_off(self):
		for candidate, origins, apps in (
			("https://example.com", "", ""),
			("example.com", "garbage", ""),
			("example.com", "http://example.com", ""),
			("example.com", "https://elsewhere.example", ""),
			("example.com", "", "android:apk-key-hash:invalid"),
		):
			with self.subTest(candidate=candidate, origins=origins, apps=apps):
				with self.assertRaises(frappe.ValidationError):
					get_rp_id_change_impact(candidate, origins, apps)

	def test_runtime_http_origin_remains_operational_in_preview(self):
		frappe.conf.host_name = "http://example.com"
		out = get_rp_id_change_impact("example.com", "", "")
		self.assertFalse(out["new_off"])
		self.assertEqual(out["new_rp_id"], "example.com")

	def test_summary_includes_disabled_and_flagged_but_bulk_keeps_flagged(self):
		current = make_credential(self.user)
		stale = make_credential(self.user, rp_id="other.example")
		disabled = make_credential(self.user, rp_id="other.example", enabled=0)
		blank = make_credential(self.user, rp_id="")
		flagged = make_credential(self.user, rp_id="other.example", flagged=1)
		expected = {"site_rp_id": "example.com", "passkeys": 4, "users": 1, "removable": 3}
		self.assertEqual(rp_admin.stale_passkey_summary(), expected)
		self.assertEqual(get_settings_context()["stale_passkeys"], expected)
		with patch("frappe.sendmail") as mail:
			self.assertEqual(remove_stale_passkeys("example.com"), {"removed": 3})
		self.assertEqual(mail.call_count, 3)
		for call in mail.call_args_list:
			self.assertEqual(call.kwargs["recipients"], [self.user])
			self.assertEqual(call.kwargs["subject"], "A passkey was removed from your account")
		for row in (stale, disabled, blank):
			self.assertFalse(frappe.db.exists("WebAuthn Credential", row.name))
		for row in (current, flagged):
			self.assertTrue(frappe.db.exists("WebAuthn Credential", row.name))

	def test_off_and_changed_argument_refuse_without_deleting(self):
		row = make_credential(self.user, rp_id="other.example")
		with self.assertRaisesRegex(frappe.ValidationError, "changed since"):
			remove_stale_passkeys("old.example")
		frappe.db.set_single_value(
			"Passkey Settings", {"passkey_rp_id": "outside.example", "passkey_origins": ""}
		)
		flush_settings_cache()
		self.assertIsNone(rp_admin.stale_passkey_summary())
		self.assertIsNone(get_resolved_rp_id()["site_rp_id"])
		with self.assertRaisesRegex(frappe.ValidationError, "Fix the RP ID first"):
			remove_stale_passkeys("outside.example")
		self.assertTrue(frappe.db.exists("WebAuthn Credential", row.name))

	def test_rp_metadata_is_visible_read_only_and_filterable(self):
		field = frappe.get_meta("WebAuthn Credential").get_field("rp_id")
		self.assertFalse(field.hidden)
		self.assertTrue(field.read_only)
		self.assertTrue(field.in_list_view)
		self.assertTrue(field.in_standard_filter)
		self.assertEqual(
			field.description,
			"The RP ID this passkey was made for. It works only while the site's RP ID is exactly this value.",
		)
		field = frappe.get_meta("Passkey Settings").get_field("passkey_rp_id")
		self.assertIn("until it is changed back", field.description)
		self.assertNotIn("cannot be undone", field.description)

	def test_app_only_candidate_and_explicit_empty_origins(self):
		make_credential(self.user, rp_id="other.example")
		app = "android:apk-key-hash:" + "A" * 43
		out = get_rp_id_change_impact("other.example", "", app)
		self.assertEqual(out["new_rp_id"], "other.example")
		self.assertFalse(out["new_off"])
		self.assertEqual(out["start"], {"passkeys": 1, "users": 1})
		with self.assertRaises(frappe.ValidationError):
			get_rp_id_change_impact("other.example")

	def test_bulk_propagates_missing_related_document_errors(self):
		make_credential(self.user, rp_id="other.example")
		with patch("frappe.delete_doc", side_effect=frappe.DoesNotExistError(doctype="User")):
			with self.assertRaises(frappe.DoesNotExistError):
				remove_stale_passkeys("example.com")

	def test_resolved_rp_exposes_operational_rp(self):
		self.assertEqual(get_resolved_rp_id()["site_rp_id"], "example.com")

	def test_permissions_methods_and_impersonation(self):
		for endpoint in (get_rp_id_change_impact, remove_stale_passkeys):
			self.assertEqual(tuple(frappe.allowed_http_methods_for_whitelisted_func[endpoint]), ("POST",))
			for user in ("Guest", self.user):
				sign_in(user)
				with patch.dict(frappe.flags, {"in_test": False}):
					with self.assertRaises(frappe.PermissionError):
						endpoint("example.com")
		sign_in("Administrator")
		frappe.session.data.impersonated_by = self.user
		try:
			with self.assertRaises(ImpersonatedSessionRefused):
				remove_stale_passkeys("example.com")
		finally:
			frappe.session.data.pop("impersonated_by", None)

	def test_rate_limits(self):
		for endpoint, limit in ((get_rp_id_change_impact, 30), (remove_stale_passkeys, 3)):
			for _ in range(limit):
				endpoint("example.com")
			with self.assertRaises(frappe.TooManyRequestsError):
				endpoint("example.com")
