# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Enrollment-enforcement verdict (F2): the server-owned ``enforcement`` boot block —
policy rung resolution (incl. ``Enforce After Date`` against the server clock), scope /
exempt-role membership, grace-login budget, and the ``record_enforcement`` endpoint."""

from unittest.mock import patch

import frappe
from frappe.utils import add_to_date, cint, now_datetime, nowdate

from passkeys import boot, notifications, passkey
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_user

RP_ID = "example.com"

_FIELDS = (
	"passkey_rp_id",
	"passkey_origins",
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_enrollment_policy",
	"passkey_enforce_after",
	"passkey_enforce_scope",
	"passkey_enforce_grace_logins",
	"passkey_enforce_incapable",
	"passkey_enforce_allow_hybrid",
)


class EnforcementVerdictTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enrollment_policy = "Enforce"
		settings.passkey_enforce_after = None
		settings.passkey_enforce_scope = "All Users"
		settings.passkey_enforce_grace_logins = 3
		settings.passkey_enforce_incapable = "Degrade to Nudge"
		settings.passkey_enforce_allow_hybrid = 1
		settings.set("passkey_enforce_roles", [])
		settings.set("passkey_enforce_exempt_roles", [{"role": "System Manager"}])
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		doc = frappe.get_doc("Passkey Settings")
		for field in _FIELDS:
			doc.set(field, self._snapshot.get(field))
		doc.set("passkey_enforce_roles", [])
		doc.set("passkey_enforce_exempt_roles", [{"role": "System Manager"}])
		doc.flags.ignore_permissions = True
		doc.save()
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _set(self, **scalars):
		for field, value in scalars.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _user(self, roles=None) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_enforce"}
		)
		self.addCleanup(
			frappe.db.delete,
			"DefaultValue",
			{"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_incapable_notified"},
		)
		if roles:
			frappe.get_doc("User", user).add_roles(*roles)
		return user

	def _verdict(self, user, creds=0):
		return boot.build_enforcement(user, self._settings(), creds)

	# ---- rung resolution ------------------------------------------------

	def test_enforce_in_scope_zero_creds_within_grace(self):
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])
		self.assertFalse(v["blocking"])
		self.assertEqual(v["grace_remaining"], 3)
		self.assertEqual(v["reason"], "grace")
		self.assertTrue(v["allow_hybrid"])
		self.assertEqual(v["incapable_policy"], "degrade")

	def test_grace_zero_blocks_immediately(self):
		self._set(passkey_enforce_grace_logins=0)
		v = self._verdict(self._user())
		self.assertTrue(v["blocking"])
		self.assertEqual(v["grace_remaining"], 0)
		self.assertEqual(v["reason"], "blocking")

	def test_having_a_credential_satisfies_enforcement(self):
		user = self._user()
		make_credential(user)
		v = self._verdict(user, creds=1)
		self.assertTrue(v["in_scope"])
		self.assertFalse(v["blocking"])
		self.assertEqual(v["reason"], "satisfied")

	def test_off_and_nudge_are_not_in_scope(self):
		self._set(passkey_enrollment_policy="Off")
		self.assertFalse(self._verdict(self._user())["in_scope"])
		self._set(passkey_enrollment_policy="Nudge")
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "nudge")
		self.assertFalse(v["in_scope"])

	def test_no_login_mode_makes_enforcement_inert(self):
		self._set(login_with_passkey=0, passkey_as_second_factor=0)
		v = self._verdict(self._user())
		self.assertFalse(v["in_scope"])
		self.assertFalse(v["blocking"])

	# ---- scope + exemptions --------------------------------------------

	def test_exempt_role_is_break_glass(self):
		# System Manager is seeded exempt by default → never in scope.
		self.assertFalse(self._verdict(self._user(roles=["System Manager"]))["in_scope"])

	def test_selected_roles_scope_membership(self):
		self._set(passkey_enforce_scope="Selected Roles")
		# rebuild the roles child table on the settings doc
		doc = frappe.get_doc("Passkey Settings")
		doc.set("passkey_enforce_roles", [{"role": "Sales User"}])
		doc.flags.ignore_permissions = True
		doc.save()
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self.assertFalse(self._verdict(self._user())["in_scope"])  # no Sales User role
		self.assertTrue(self._verdict(self._user(roles=["Sales User"]))["in_scope"])

	# ---- Enforce After Date (server clock) -----------------------------

	def test_enforce_after_future_date_behaves_as_nudge(self):
		self._set(
			passkey_enrollment_policy="Enforce After Date",
			passkey_enforce_after=add_to_date(nowdate(), days=7),
		)
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "nudge")
		self.assertFalse(v["in_scope"])

	def test_enforce_after_past_date_behaves_as_enforce(self):
		self._set(
			passkey_enrollment_policy="Enforce After Date",
			passkey_enforce_after=add_to_date(nowdate(), days=-1),
		)
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])

	# ---- grace budget (defer counter) ----------------------------------

	def test_deferrals_spend_the_grace_budget_then_block(self):
		user = self._user()
		self.assertEqual(self._verdict(user)["grace_remaining"], 3)
		boot.record_enforcement_event(user, "defer")
		boot.record_enforcement_event(user, "defer")
		self.assertEqual(self._verdict(user)["grace_remaining"], 1)
		self.assertFalse(self._verdict(user)["blocking"])
		boot.record_enforcement_event(user, "defer")
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 0)
		self.assertTrue(v["blocking"])

	# ---- record_enforcement endpoint -----------------------------------

	def test_record_enforcement_defer_folds_state(self):
		user = self._user()
		frappe.set_user(user)
		result = passkey.record_enforcement("defer")
		self.assertEqual(result["enforcement_state"]["grace_used"], 1)

	def test_record_enforcement_incapable_returns_state(self):
		user = self._user()
		frappe.set_user(user)
		# Degrade policy ⇒ no admin advisory; still returns the (unchanged) state.
		result = passkey.record_enforcement("incapable")
		self.assertEqual(cint(result["enforcement_state"]["grace_used"]), 0)

	def test_incapable_under_block_notify_records_admin_advisory(self):
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		frappe.set_user(user)
		passkey.record_enforcement("incapable")
		frappe.set_user("Administrator")
		self.assertTrue(
			frappe.db.exists("Activity Log", {"user": user, "content": "passkeys:enforce_incapable_device"})
		)

	def test_incapable_admin_advisory_is_deduped_within_the_window(self):
		# A single incapable user must not flood admins: the client once-guard resets per
		# page load, so the server dedups the email to one per user per 24h — but the
		# Activity Log risk event (telemetry) still records on every report.
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		frappe.set_user(user)
		with (
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.sendmail") as mock_send,
		):
			passkey.record_enforcement("incapable")
			passkey.record_enforcement("incapable")
			passkey.record_enforcement("incapable")
		self.assertEqual(mock_send.call_count, 1, "admins are emailed at most once within the dedup window")
		frappe.set_user("Administrator")
		rows = frappe.get_all(
			"Activity Log", filters={"user": user, "content": "passkeys:enforce_incapable_device"}
		)
		self.assertEqual(
			len(rows), 3, "the Activity Log risk event still records every time (dedup gates only the email)"
		)

	def test_incapable_admin_advisory_reemails_after_the_window_lapses(self):
		# Past the dedup window a fresh report re-alerts admins (the backdated marker
		# simulates a report a day later).
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		frappe.set_user(user)
		with (
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.sendmail") as mock_send,
		):
			passkey.record_enforcement("incapable")
			stale = add_to_date(now_datetime(), hours=-25).isoformat()
			frappe.db.set_default(f"{user}_passkey_incapable_notified", stale, parent=DEFAULTS_PARENT)
			passkey.record_enforcement("incapable")
		self.assertEqual(mock_send.call_count, 2, "a report past the dedup window re-emails admins")

	def test_record_enforcement_rejects_unknown_event(self):
		user = self._user()
		frappe.set_user(user)
		with self.assertRaises(frappe.ValidationError):
			passkey.record_enforcement("bogus")

	def test_record_enforcement_requires_auth(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.AuthenticationError):
			passkey.record_enforcement("defer")

	# ---- report-only preview -------------------------------------------

	def test_would_be_blocked_count_preview_for_system_manager(self):
		self._user()  # in scope, 0 creds — counted
		make_credential(self._user())  # enrolled ⇒ excluded from the count
		frappe.set_user("Administrator")
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		count = info.passkeys["settings_context"]["would_be_blocked_count"]
		self.assertIsInstance(count, int)
		self.assertGreaterEqual(count, 1)  # at least our zero-credential test user
