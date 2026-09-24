# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Enrollment-enforcement verdict: the server-owned ``enforcement`` boot block —
per-user rung (scope, System Managers, Starting on, Everyone else), exempt-role
membership, grace-login budget, and the ``record_enforcement`` endpoint."""

from unittest.mock import patch

import frappe
from frappe.utils import add_to_date, cint, now_datetime, nowdate

from passkeys import boot, enforcement_admin, notifications, passkey, state
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_user, sign_in

RP_ID = "example.com"

_FIELDS = (
	"passkey_rp_id",
	"passkey_origins",
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_enforce_after",
	"passkey_enforce_scope",
	"passkey_enforce_privileged_always",
	"passkey_everyone_else",
	"passkey_enforce_grace_logins",
	"passkey_enforce_incapable",
	"passkey_nudge_max_prompts",
	"passkey_nudge_cooldown_days",
)


class EnforcementVerdictTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = "https://example.com"
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enforce_after = None
		settings.passkey_enforce_scope = "All users"
		settings.passkey_enforce_privileged_always = 1
		settings.passkey_everyone_else = "Nudge"
		settings.passkey_enforce_grace_logins = 3
		settings.passkey_enforce_incapable = "Degrade to Nudge"
		settings.set("passkey_enforce_roles", [])
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		# This battery's record_enforcement legs send an admin advisory (frappe.sendmail
		# enqueues + commits), which durably commits the modes-on Passkey Settings write
		# past the runner's per-test savepoint rollback. Restore the pre-test snapshot and
		# COMMIT it, mirroring test_passkey_only_veto/_SweptBase, so the modes never leak.
		# Raw writes: the snapshot is whatever the previous test left, which need not pass
		# the settings validators, so a validated save() could refuse to put it back.
		sign_in("Administrator")
		for field in _FIELDS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field))
		frappe.db.delete("Passkey Enforcement Role", {"parent": "Passkey Settings"})
		flush_settings_cache()
		frappe.db.commit()  # must survive past the (per-class) rollback

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _set(self, **scalars):
		for field, value in scalars.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		flush_settings_cache()

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

	def _set_enforced_roles(self, *roles):
		doc = frappe.get_doc("Passkey Settings")
		doc.set("passkey_enforce_roles", [{"role": role} for role in roles])
		doc.flags.ignore_permissions = True
		doc.save()
		flush_settings_cache()

	# ---- rung resolution ------------------------------------------------

	def test_enforce_in_scope_zero_creds_within_grace(self):
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])
		self.assertFalse(v["blocking"])
		self.assertEqual(v["grace_remaining"], 3)
		self.assertEqual(v["reason"], "grace")
		self.assertTrue(v["enforcing"])
		self.assertFalse(any("hybrid" in key for key in v))
		self.assertNotIn("policy", v)
		self.assertEqual(v["incapable_policy"], "degrade")

	def test_non_mapping_enforcement_state_falls_back_to_zero(self):
		user = self._user()
		for raw in ("null", "[]", "1"):
			with self.subTest(raw=raw):
				frappe.db.set_default(f"{user}_passkey_enforce", raw, parent=DEFAULTS_PARENT)
				self.assertEqual(boot.get_enforcement_state(user), {"grace_used": 0})

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

	def test_everyone_else_off_and_nudge_are_not_in_scope(self):
		self._set(
			passkey_enforce_scope="No one",
			passkey_enforce_privileged_always=0,
			passkey_everyone_else="Off",
		)
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "off")
		self.assertFalse(v["in_scope"])
		self.assertFalse(v["enforcing"])
		self._set(passkey_everyone_else="Nudge")
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "nudge")
		self.assertFalse(v["in_scope"])

	def test_no_login_mode_makes_enforcement_inert(self):
		self._set(login_with_passkey=0, passkey_as_second_factor=0)
		v = self._verdict(self._user())
		self.assertFalse(v["in_scope"])
		self.assertFalse(v["blocking"])

	# ---- scope + exemptions --------------------------------------------

	def test_marker_role_is_per_user_break_glass(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		self.assertIn(boot.EXEMPT_ROLE, set(frappe.get_roles(user)))
		self.assertFalse(self._verdict(user)["in_scope"])

	def test_selected_roles_scope_membership(self):
		self._set(passkey_enforce_scope="Selected roles")
		self._set_enforced_roles("Sales User")
		self.assertFalse(self._verdict(self._user())["in_scope"])  # no Sales User role
		self.assertTrue(self._verdict(self._user(roles=["Sales User"]))["in_scope"])

	def test_privileged_always_includes_system_manager_under_selected_roles(self):
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=1)
		self._set_enforced_roles("Sales User")
		self.assertTrue(self._verdict(self._user(roles=["System Manager"]))["in_scope"])

	def test_privileged_opt_out_excludes_system_manager_under_selected_roles(self):
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=0)
		self._set_enforced_roles("Sales User")
		self.assertFalse(self._verdict(self._user(roles=["System Manager"]))["in_scope"])

	def test_marker_role_wins_over_privileged_always(self):
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=1)
		self._set_enforced_roles("Sales User")
		user = self._user(roles=["System Manager"])
		enforcement_admin.set_user_exemption(user, True)
		self.assertFalse(self._verdict(user)["in_scope"])

	def test_no_one_plus_privileged_enforces_system_manager_only(self):
		self._set(
			passkey_enforce_scope="No one",
			passkey_enforce_privileged_always=1,
			passkey_everyone_else="Off",
		)
		manager = self._verdict(self._user(roles=["System Manager"]))
		self.assertEqual(manager["effective"], "enforce")
		self.assertTrue(manager["in_scope"])
		outsider = self._verdict(self._user())
		self.assertEqual(outsider["effective"], "off")
		self.assertFalse(outsider["in_scope"])

	def test_everyone_else_off_does_not_nudge_non_members(self):
		self._set(
			passkey_enforce_scope="Selected roles",
			passkey_enforce_privileged_always=0,
			passkey_everyone_else="Off",
		)
		self._set_enforced_roles("Sales User")
		user = self._user()
		self.assertEqual(self._verdict(user)["effective"], "off")
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	def test_everyone_else_nudge_prompts_non_members(self):
		self._set(
			passkey_enforce_scope="Selected roles",
			passkey_enforce_privileged_always=0,
			passkey_everyone_else="Nudge",
		)
		self._set_enforced_roles("Sales User")
		user = self._user()
		self.assertEqual(self._verdict(user)["effective"], "nudge")
		self.assertTrue(boot.nudge_eligible(user, self._settings(), 0))

	def test_exempt_takes_everyone_else(self):
		self._set(passkey_everyone_else="Off", passkey_enforce_privileged_always=1)
		user = self._user(roles=["System Manager"])
		enforcement_admin.set_user_exemption(user, True)
		self.assertEqual(self._verdict(user)["effective"], "off")
		self.assertFalse(self._verdict(user)["in_scope"])
		self._set(passkey_everyone_else="Nudge")
		self.assertEqual(self._verdict(user)["effective"], "nudge")

	# ---- Starting on (server clock) ------------------------------------

	def test_future_start_date_behaves_as_nudge(self):
		self._set(passkey_enforce_after=add_to_date(nowdate(), days=7))
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "nudge")
		self.assertFalse(v["in_scope"])

	def test_past_start_date_behaves_as_enforce(self):
		self._set(passkey_enforce_after=add_to_date(nowdate(), days=-1))
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])

	def test_blank_start_date_enforces_immediately(self):
		self._set(passkey_enforce_after=None)
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])

	# ---- grace budget (defer counter) ----------------------------------

	def test_deferrals_spend_the_grace_budget_then_block(self):
		user = self._user()
		self.assertEqual(self._verdict(user)["grace_remaining"], 3)
		boot.record_enforcement_defer(user)
		boot.record_enforcement_defer(user)
		self.assertEqual(self._verdict(user)["grace_remaining"], 1)
		self.assertFalse(self._verdict(user)["blocking"])
		boot.record_enforcement_defer(user)
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 0)
		self.assertTrue(v["blocking"])

	def test_nondefault_grace_budget_owns_the_exact_boundary(self):
		# The product-owner report: grace "is only three, always three". Prove the
		# configured value — not a hardcoded default — drives the verdict, and that the
		# block arrives at EXACTLY the configured deferral, never the default 3.
		self._set(passkey_enforce_grace_logins=5)
		user = self._user()
		self.assertEqual(self._verdict(user)["grace_remaining"], 5)
		# Three deferrals: a hardcoded-3 budget would already be blocking here — it must not.
		for _ in range(3):
			boot.record_enforcement_defer(user)
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 2)
		self.assertFalse(v["blocking"])
		self.assertEqual(v["reason"], "grace")
		# Fourth deferral: still one grace login left — not yet blocking.
		boot.record_enforcement_defer(user)
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 1)
		self.assertFalse(v["blocking"])
		# Fifth (the configured boundary) spends the last grace login → the verdict flips.
		boot.record_enforcement_defer(user)
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 0)
		self.assertTrue(v["blocking"])
		self.assertEqual(v["reason"], "blocking")

	# ---- record_enforcement endpoint -----------------------------------

	def test_record_enforcement_defer_folds_state(self):
		user = self._user()
		sign_in(user)
		first = passkey.record_enforcement("defer")
		second = passkey.record_enforcement("defer")
		self.assertEqual(first["enforcement_state"]["grace_used"], 1)
		self.assertEqual(second["enforcement_state"]["grace_used"], 1)
		self.assertEqual(boot.get_enforcement_state(user)["grace_used"], 1)

	def test_record_enforcement_ignores_off_nudge_and_future_date(self):
		cases = (
			{
				"passkey_enforce_scope": "No one",
				"passkey_enforce_privileged_always": 0,
				"passkey_everyone_else": "Off",
				"passkey_enforce_after": None,
			},
			{
				"passkey_enforce_scope": "No one",
				"passkey_enforce_privileged_always": 0,
				"passkey_everyone_else": "Nudge",
				"passkey_enforce_after": None,
			},
			{
				"passkey_enforce_scope": "All users",
				"passkey_enforce_after": add_to_date(nowdate(), days=7),
			},
		)
		for scalars in cases:
			with self.subTest(scalars=scalars):
				self._set(**scalars)
				user = self._user()
				boot.record_enforcement_defer(user)
				sign_in(user)
				with (
					patch.object(state, "claim_enforcement_defer") as claim_defer,
					patch.object(notifications, "record_enforcement_incapable") as report_incapable,
				):
					defer = passkey.record_enforcement("defer")
					incapable = passkey.record_enforcement("incapable")
				claim_defer.assert_not_called()
				report_incapable.assert_not_called()
				self.assertEqual(defer["enforcement_state"], {"grace_used": 1})
				self.assertEqual(incapable["enforcement_state"], {"grace_used": 1})
				self.assertEqual(boot.get_enforcement_state(user), {"grace_used": 1})

	def test_record_enforcement_ignores_exempt_and_out_of_role_users(self):
		self._set(passkey_enforce_scope="Selected roles")
		self._set_enforced_roles("Sales User")
		out_of_role = self._user()
		exempt = self._user(roles=["Sales User"])
		enforcement_admin.set_user_exemption(exempt, True)
		for user in (out_of_role, exempt):
			with self.subTest(user=user):
				sign_in(user)
				with (
					patch.object(state, "claim_enforcement_defer") as claim_defer,
					patch.object(notifications, "record_enforcement_incapable") as report_incapable,
				):
					passkey.record_enforcement("defer")
					passkey.record_enforcement("incapable")
				claim_defer.assert_not_called()
				report_incapable.assert_not_called()
				self.assertEqual(boot.get_enforcement_state(user), {"grace_used": 0})

	def test_record_enforcement_ignores_enrolled_user(self):
		user = self._user()
		make_credential(user)
		sign_in(user)
		with (
			patch.object(state, "claim_enforcement_defer") as claim_defer,
			patch.object(notifications, "record_enforcement_incapable") as report_incapable,
		):
			passkey.record_enforcement("defer")
			passkey.record_enforcement("incapable")
		claim_defer.assert_not_called()
		report_incapable.assert_not_called()
		self.assertEqual(boot.get_enforcement_state(user), {"grace_used": 0})

	def test_record_enforcement_does_not_defer_after_grace_is_exhausted(self):
		self._set(passkey_enforce_grace_logins=1)
		user = self._user()
		boot.record_enforcement_defer(user)
		sign_in(user)
		with patch.object(state, "claim_enforcement_defer") as claim_defer:
			result = passkey.record_enforcement("defer")
		claim_defer.assert_not_called()
		self.assertEqual(result["enforcement_state"]["grace_used"], 1)

	def test_record_enforcement_incapable_returns_state(self):
		user = self._user()
		sign_in(user)
		with patch.object(notifications, "record_enforcement_incapable") as report_incapable:
			result = passkey.record_enforcement("incapable")
		report_incapable.assert_not_called()
		self.assertEqual(cint(result["enforcement_state"]["grace_used"]), 0)
		self.assertFalse(frappe.db.exists("DefaultValue", {"defkey": f"{user}_passkey_enforce"}))

	def test_blocking_incapable_report_is_still_applicable(self):
		self._set(passkey_enforce_grace_logins=0, passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		sign_in(user)
		with patch.object(notifications, "record_enforcement_incapable") as report_incapable:
			passkey.record_enforcement("incapable")
		report_incapable.assert_called_once_with(user)

	def test_incapable_under_block_notify_records_admin_advisory(self):
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		sign_in(user)
		with (
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.sendmail"),
		):
			passkey.record_enforcement("incapable")
		sign_in("Administrator")
		self.assertTrue(
			frappe.db.exists("Activity Log", {"user": user, "content": "passkeys:enforce_incapable_device"})
		)

	def test_incapable_admin_advisory_is_deduped_within_the_window(self):
		# A single incapable user must not flood admins: the client once-guard resets per
		# page load, so the server dedups the email to one per user per 24h — but the
		# Activity Log risk event (telemetry) still records on every report.
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		sign_in(user)
		with (
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.sendmail") as mock_send,
		):
			passkey.record_enforcement("incapable")
			passkey.record_enforcement("incapable")
			passkey.record_enforcement("incapable")
		self.assertEqual(mock_send.call_count, 1, "admins are emailed at most once within the dedup window")
		sign_in("Administrator")
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
		sign_in(user)
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
		sign_in(user)
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
		sign_in("Administrator")
		info = frappe._dict()
		boot.extend_bootinfo(bootinfo=info)
		count = info.passkeys["settings_context"]["would_be_blocked_count"]
		self.assertIsInstance(count, int)
		self.assertGreaterEqual(count, 1)  # at least our zero-credential test user

	def test_administrator_scope_uses_assigned_roles_not_every_role(self):
		# get_roles("Administrator") returns every Role. Once the exempt marker
		# exists, that used to mark Administrator exempt and in every selected role.
		enforcement_admin._ensure_exempt_role()
		self.assertFalse(
			frappe.db.exists(
				"Has Role",
				{"parent": "Administrator", "parenttype": "User", "role": boot.EXEMPT_ROLE},
			)
		)
		self.assertTrue(self._verdict("Administrator")["in_scope"])
		self.assertFalse(enforcement_admin.admin_enforcement_view("Administrator")["exempt"])

		scope_role = "Passkeys Test Scope Role"
		if not frappe.db.exists("Role", scope_role):
			frappe.get_doc({"doctype": "Role", "role_name": scope_role}).insert(ignore_permissions=True)
		self.addCleanup(frappe.delete_doc, "Role", scope_role, force=1, ignore_permissions=True)
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=0)
		self._set_enforced_roles(scope_role)
		self.assertFalse(self._verdict("Administrator")["in_scope"])

		self._set(passkey_enforce_privileged_always=1)
		self.assertTrue(self._verdict("Administrator")["in_scope"])
		self.assertTrue(self._verdict(self._user(roles=["System Manager"]))["in_scope"])

	def test_defer_reads_current_database_state(self):
		user = self._user()
		boot.record_enforcement_defer(user)
		self.assertEqual(boot.get_enforcement_state(user)["grace_used"], 1)
		frappe.db.set_value(
			"DefaultValue",
			{"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_enforce"},
			"defvalue",
			frappe.as_json({"grace_used": 2}),
		)
		self.assertEqual(boot.record_enforcement_defer(user)["grace_used"], 3)
		self.assertEqual(boot.get_enforcement_state(user)["grace_used"], 3)

	def test_degrade_nudge_uses_ordinary_thresholds(self):
		self._set(passkey_nudge_max_prompts=3, passkey_nudge_cooldown_days=30)
		user = self._user()
		self.assertTrue(self._verdict(user)["degrade_nudge_eligible"])
		self.assertFalse(self._verdict(user, creds=1)["degrade_nudge_eligible"])
		boot.record_nudge_event(user, "opt_out")
		self.assertFalse(self._verdict(user)["degrade_nudge_eligible"])
		for nudge_state in (
			{"declines": 3, "opt_out": 0, "last_shown": None},
			{"declines": 1, "opt_out": 0, "last_shown": now_datetime().isoformat()},
		):
			with self.subTest(nudge_state=nudge_state):
				frappe.db.set_default(
					f"{user}_passkey_nudge", frappe.as_json(nudge_state), parent=DEFAULTS_PARENT
				)
				self.assertFalse(self._verdict(user)["degrade_nudge_eligible"])

	def test_degrade_nudge_requires_degrade_and_scope(self):
		self._set(passkey_nudge_max_prompts=3, passkey_nudge_cooldown_days=30)
		user = self._user()
		self._set(passkey_enforce_incapable="Block + Notify Admin")
		self.assertFalse(self._verdict(user)["degrade_nudge_eligible"])
		self._set(passkey_enforce_incapable="Degrade to Nudge", passkey_enforce_scope="Selected roles")
		self.assertFalse(self._verdict(user)["degrade_nudge_eligible"])
		for everyone_else in ("Off", "Nudge"):
			self._set(passkey_everyone_else=everyone_else, passkey_enforce_privileged_always=0)
			with patch.object(boot, "get_nudge_state") as read_nudge:
				self.assertFalse(self._verdict(user)["degrade_nudge_eligible"])
			read_nudge.assert_not_called()

	def test_boot_reuses_nudge_state_for_degrade_verdict(self):
		self._set(passkey_nudge_max_prompts=3, passkey_nudge_cooldown_days=30)
		user = self._user()
		with patch.object(boot, "get_nudge_state", wraps=boot.get_nudge_state) as read_nudge:
			payload = boot.build_passkeys_boot(user)
		read_nudge.assert_called_once_with(user)
		self.assertTrue(payload["enforcement"]["degrade_nudge_eligible"])
		self.assertFalse(payload["nudge_state"]["eligible"])
		self.assertFalse(payload["upsell_eligible"])
