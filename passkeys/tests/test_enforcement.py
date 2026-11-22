# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Enrollment-enforcement verdict: the server-owned ``enforcement`` boot block —
per-user rung (scope, System Managers, Starting on, Everyone else), exempt-role
membership, grace-login budget, and the ``record_enforcement`` endpoint."""

import json
from unittest.mock import patch

import frappe
import redis
from frappe.utils import add_to_date, cint, get_datetime, now_datetime, nowdate

from passkeys import boot, enforcement_admin, notifications, passkey, state
from passkeys.errors import ImpersonatedSessionRefused, PasskeyServedByCore
from passkeys.install import DEFAULTS_PARENT
from passkeys.passkeys.doctype.passkey_settings import passkey_settings
from passkeys.tests.committed_state import delete_fixture, restore_rows
from passkeys.tests.compat import IntegrationTestCase, PinnedSiteRp, activity_log_count, flush_settings_cache
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


class EnforcementVerdictTest(PinnedSiteRp, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._roles = frappe.db.get_values(
			"Passkey Enforcement Role",
			{"parent": "Passkey Settings", "parenttype": "Passkey Settings"},
			"*",
			as_dict=True,
		)
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
		# Mail delivery can commit; restore settings for the next test in this class.
		sign_in("Administrator")
		for field in _FIELDS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field))
		restore_rows(
			"Passkey Enforcement Role",
			{"parent": "Passkey Settings", "parenttype": "Passkey Settings"},
			self._roles,
		)
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
		self.addCleanup(
			delete_fixture, "User", user, force=1, ignore_permissions=True, delete_permanently=True
		)
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

	def test_exemption_is_per_user_break_glass(self):
		user = self._user()
		enforcement_admin.set_user_exemption(user, True)
		self.addCleanup(boot.set_exempt, user, False)
		self.assertTrue(boot.is_exempt(user))
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
		self.assertTrue(activity_log_count({"user": user, "content": "passkeys:enforce_incapable_device"}))

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

	def test_impersonated_session_spends_no_grace_and_reports_nothing(self):
		# An impersonating admin must not burn the user's grace toward a lockout, nor file
		# an incapable-device report (and admin email) about the admin's own device.
		self._set(passkey_enforce_grace_logins=1, passkey_enforce_incapable="Block + Notify Admin")
		user = self._user()
		sign_in(user)
		frappe.session.data.impersonated_by = "Administrator"
		self.addCleanup(frappe.session.data.pop, "impersonated_by", None)
		counter = f"{state.RATE_LIMIT_PREFIX}record_enforcement:{user}"
		self.addCleanup(state.clear_counter, counter)
		with (
			patch.object(state, "claim_enforcement_defer") as claim_defer,
			patch.object(notifications, "record_enforcement_incapable") as report_incapable,
		):
			for event in boot.ENFORCE_EVENTS:
				with (
					self.subTest(event=event),
					self.assertRaises(ImpersonatedSessionRefused),
				):
					passkey.record_enforcement(event)
		claim_defer.assert_not_called()
		report_incapable.assert_not_called()
		self.assertEqual(boot.get_enforcement_state(user), {"grace_used": 0})
		self.assertEqual(self._verdict(user)["reason"], "grace")  # not blocking
		self.assertEqual(state.get_counter(counter), 0)

		frappe.session.data.pop("impersonated_by")
		self.assertEqual(passkey.record_enforcement("defer")["enforcement_state"], {"grace_used": 1})
		self.assertTrue(self._verdict(user)["blocking"])

	# ---- report-only preview -------------------------------------------

	def _clear_preview_cache(self):
		key = f"passkeys:test-enforcement-preview:{frappe.generate_hash(length=12)}"
		cache_key = patch.object(boot, "ENFORCEMENT_PREVIEW_KEY", key)
		cache_key.start()
		self.addCleanup(cache_key.stop)
		self.addCleanup(frappe.cache.delete, frappe.cache.make_key(key))
		for method in (
			"get_settings_context",
			"recalculate_enforcement_preview",
			"count_enforcement_draft",
			"get_enforcement_preview",
		):
			key = f"{state.RATE_LIMIT_PREFIX}{method}:Administrator"
			state.clear_counter(key)
			self.addCleanup(state.clear_counter, key)

	def test_settings_context_reads_empty_cache_without_computing(self):
		self._clear_preview_cache()
		sign_in("Administrator")
		with (
			patch.object(boot, "refresh_enforcement_preview") as preview,
			patch.object(boot, "count_users_to_enroll") as count,
			patch.object(frappe, "get_all") as scan,
			patch.object(frappe, "enqueue") as enqueue,
		):
			context = passkey_settings.get_settings_context()
		self.assertIsNone(context["enforcement_preview"])
		self.assertNotIn("configured_site_origin", context)
		preview.assert_not_called()
		count.assert_not_called()
		scan.assert_not_called()
		enqueue.assert_not_called()

	def test_background_preview_counts_saved_scope_and_enabled_credentials(self):
		self._clear_preview_cache()
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=0)
		role = "Passkeys Preview Test Role"
		frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
		self.addCleanup(
			delete_fixture, "Role", role, force=1, ignore_permissions=True, delete_permanently=True
		)
		self._set_enforced_roles(role)
		self._user([role])  # counted
		make_credential(self._user([role]), enabled=0)  # also counted
		make_credential(self._user([role]))  # enrolled
		self._user()  # outside selected roles
		exempt = self._user([role])
		boot.set_exempt(exempt, True)
		self.addCleanup(boot.set_exempt, exempt, False)
		disabled = self._user([role])
		frappe.db.set_value("User", disabled, "enabled", 0)
		sign_in("Administrator")
		boot.refresh_enforcement_preview()
		preview = passkey_settings.get_settings_context()["enforcement_preview"]
		self.assertEqual(preview["count"], 2)
		self.assertEqual(set(preview), {"count", "computed_at", "scan"})
		self.assertLessEqual(get_datetime(preview["computed_at"]), now_datetime())
		name = frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY)
		self.assertGreater(frappe.cache.ttl(name), boot.ENFORCEMENT_PREVIEW_TTL - 60)
		self.assertLessEqual(frappe.cache.ttl(name), boot.ENFORCEMENT_PREVIEW_TTL)

	def test_preview_only_shows_the_current_saved_policy(self):
		self._clear_preview_cache()
		self._user()
		boot.refresh_enforcement_preview()
		self.assertGreater(boot.settings_banner_context()["enforcement_preview"]["count"], 0)
		self._set(passkey_enforce_scope="No one", passkey_enforce_privileged_always=0)
		self.assertIsNone(boot.settings_banner_context()["enforcement_preview"])
		boot.refresh_enforcement_preview()
		self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["count"], 0)

	def test_older_policy_job_finishing_last_cannot_replace_current_preview(self):
		self._clear_preview_cache()
		self._user()
		old_settings = frappe.get_doc("Passkey Settings")
		self._set(passkey_enforce_scope="No one", passkey_enforce_privileged_always=0)
		boot.refresh_enforcement_preview()
		current_preview = boot.settings_banner_context()["enforcement_preview"]
		self.assertEqual(current_preview["count"], 0)
		get_doc = frappe.get_doc
		with patch.object(
			frappe,
			"get_doc",
			side_effect=lambda *args, **kwargs: (
				old_settings if args == ("Passkey Settings",) else get_doc(*args, **kwargs)
			),
		):
			boot.refresh_enforcement_preview()
		old_signature = boot.enforcement_preview_signature(old_settings)
		old_result = frappe.cache.hmget(
			frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY), [f"result:{old_signature}"]
		)[0]
		self.assertGreater(json.loads(old_result)["count"], 0)
		self.assertEqual(boot.settings_banner_context()["enforcement_preview"], current_preview)

	def test_earlier_scan_finishing_last_keeps_later_same_policy_result(self):
		self._clear_preview_cache()
		earlier = "2026-10-20 10:00:00.000000"
		later = "2026-10-20 09:00:00.000000"

		def scan(settings, site_rp_id):
			with (
				patch.object(frappe.utils, "now", return_value=later),
				patch.object(boot, "count_users_to_enroll", return_value=0),
			):
				boot.refresh_enforcement_preview()
			return 1

		with (
			patch.object(frappe.utils, "now", return_value=earlier),
			patch.object(boot, "count_users_to_enroll", side_effect=scan),
		):
			boot.refresh_enforcement_preview()
		self.assertEqual(
			boot.settings_banner_context()["enforcement_preview"],
			{"count": 0, "computed_at": later, "scan": 2},
		)

	def test_later_scan_replaces_earlier_result_when_clock_goes_backwards(self):
		self._clear_preview_cache()
		earlier = "2026-10-20 10:00:00.000000"
		later = "2026-10-20 09:00:00.000000"
		with (
			patch.object(frappe.utils, "now", return_value=earlier),
			patch.object(boot, "count_users_to_enroll", return_value=1),
		):
			boot.refresh_enforcement_preview()
		self.assertEqual(
			boot.settings_banner_context()["enforcement_preview"],
			{"count": 1, "computed_at": earlier, "scan": 1},
		)
		with (
			patch.object(frappe.utils, "now", return_value=later),
			patch.object(boot, "count_users_to_enroll", return_value=0),
		):
			boot.refresh_enforcement_preview()
		self.assertEqual(
			boot.settings_banner_context()["enforcement_preview"],
			{"count": 0, "computed_at": later, "scan": 2},
		)

	def test_reset_drops_an_inflight_scan_after_a_new_scan_publishes(self):
		self._clear_preview_cache()
		name = frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY)
		frappe.cache.hincrby(name, "seq", 49)

		def scan(settings, site_rp_id):
			self.assertEqual(boot.get_enforcement_preview_scan(), 50)
			frappe.cache.delete(name)
			with patch.object(boot, "count_users_to_enroll", return_value=0):
				boot.refresh_enforcement_preview()
			self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["count"], 0)
			return 1

		with patch.object(boot, "count_users_to_enroll", side_effect=scan):
			boot.refresh_enforcement_preview()
		preview = boot.settings_banner_context()["enforcement_preview"]
		self.assertEqual((preview["count"], preview["scan"]), (0, 1))

	def test_scan_from_before_a_reset_never_publishes_even_with_a_reused_number(self):
		self._clear_preview_cache()
		name = frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY)

		def scan(settings, site_rp_id):
			# Reset mid-scan, then enough new scans that the in-flight number (1) is reused.
			frappe.cache.delete(name)
			with patch.object(boot, "count_users_to_enroll", return_value=0):
				boot.refresh_enforcement_preview()
				boot.refresh_enforcement_preview()
			return 1

		with patch.object(boot, "count_users_to_enroll", side_effect=scan):
			boot.refresh_enforcement_preview()
		preview = boot.settings_banner_context()["enforcement_preview"]
		self.assertEqual((preview["count"], preview["scan"]), (0, 2))

	def test_reset_removes_previous_results_and_scan_counter(self):
		self._clear_preview_cache()
		with patch.object(boot, "count_users_to_enroll", return_value=0):
			boot.refresh_enforcement_preview()
		self.assertIsNotNone(boot.settings_banner_context()["enforcement_preview"])
		self.assertEqual(boot.get_enforcement_preview_scan(), 1)
		frappe.cache.delete(frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY))
		self.assertIsNone(boot.settings_banner_context()["enforcement_preview"])
		self.assertEqual(boot.get_enforcement_preview_scan(), 0)

	def test_settings_onload_sets_current_preview_scan(self):
		self._clear_preview_cache()
		settings = self._settings()
		settings.onload()
		self.assertEqual(settings.get_onload()["passkeys_preview_after_scan"], 0)
		frappe.cache.hincrby(frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY), "seq", 1)
		settings.onload()
		self.assertEqual(settings.get_onload()["passkeys_preview_after_scan"], 1)

	def test_preview_skips_scan_when_modes_or_enforcement_are_off(self):
		self._clear_preview_cache()
		for settings in (
			{"login_with_passkey": 0, "passkey_as_second_factor": 0},
			{
				"login_with_passkey": 1,
				"passkey_enforce_scope": "No one",
				"passkey_enforce_privileged_always": 0,
			},
		):
			with self.subTest(settings=settings):
				self._set(**settings)
				with patch.object(boot, "count_users_to_enroll") as scan:
					boot.refresh_enforcement_preview()
				scan.assert_not_called()
				self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["count"], 0)

	def test_dormant_preview_does_not_read_settings_or_scan(self):
		with (
			patch.object(boot, "dormant", return_value=True),
			patch.object(frappe, "get_doc") as settings,
			patch.object(boot, "count_users_to_enroll") as scan,
		):
			boot.refresh_enforcement_preview()
		settings.assert_not_called()
		scan.assert_not_called()

	def test_settings_save_and_recalculate_enqueue_preview(self):
		self._clear_preview_cache()
		sign_in("Administrator")
		with (
			patch.object(frappe, "enqueue") as enqueue,
			patch.object(boot, "refresh_enforcement_preview") as preview,
		):
			frappe.get_doc("Passkey Settings").save(ignore_permissions=True)
			enqueue.assert_called_once_with(
				"passkeys.boot.refresh_enforcement_preview",
				queue="long",
				enqueue_after_commit=True,
				draft=None,
			)
			enqueue.reset_mock()
			self.assertEqual(boot.get_enforcement_preview_scan(), 0)
			key = frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY)
			self.assertEqual(frappe.cache.hincrby(key, "seq", 1), 1)
			enqueue.side_effect = lambda *args, **kwargs: frappe.cache.hincrby(key, "seq", 1)
			self.assertEqual(passkey_settings.recalculate_enforcement_preview(), {"after_scan": 1})
			self.assertEqual(boot.get_enforcement_preview_scan(), 2)
			enqueue.assert_called_once()
		preview.assert_not_called()

	def _full_preview_queue(self, queue):
		frappe.msgprint("Unrelated queue notice")
		frappe.throw("Too many queued background jobs.", title="Queue Overloaded", exc=frappe.QueueOverloaded)

	def test_settings_save_succeeds_when_preview_queue_is_full(self):
		sign_in("Administrator")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_enforce_grace_logins = 7
		with (
			patch.object(frappe.local, "message_log", []),
			patch.dict(frappe.flags, {"mute_messages": False}),
			patch(
				"frappe.utils.background_jobs._check_queue_size", side_effect=self._full_preview_queue
			) as capacity,
		):
			frappe.msgprint("Unrelated save notice")
			settings.save(ignore_permissions=True)
			self.assertEqual(
				[message.message for message in frappe.local.message_log],
				["Unrelated save notice", "Unrelated queue notice"],
			)
		capacity.assert_called_once()
		self.assertEqual(
			cint(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_grace_logins")), 7
		)

	def test_recalculate_reports_full_preview_queue(self):
		sign_in("Administrator")
		with (
			patch.object(frappe.local, "message_log", []),
			patch.dict(frappe.flags, {"mute_messages": False}),
			patch(
				"frappe.utils.background_jobs._check_queue_size", side_effect=self._full_preview_queue
			) as capacity,
		):
			with self.assertRaisesRegex(frappe.QueueOverloaded, "recount could not start"):
				passkey_settings.recalculate_enforcement_preview()
			self.assertEqual(len(frappe.local.message_log), 2)
			self.assertEqual(frappe.local.message_log[0].message, "Unrelated queue notice")
			self.assertIn("recount could not start", frappe.local.message_log[1].message)
		capacity.assert_called_once()

	def test_preview_enqueue_does_not_hide_other_errors(self):
		with patch.object(frappe, "enqueue", side_effect=RuntimeError("queue unavailable")):
			self.assertRaises(RuntimeError, boot.enqueue_enforcement_preview)

	def test_settings_preview_endpoints_enforce_rate_limits(self):
		self._clear_preview_cache()
		sign_in("Administrator")
		draft = json.dumps(self._draft())
		for endpoint, args, limit, operation in (
			(passkey_settings.get_settings_context, (), 30, "settings_banner_context"),
			(passkey_settings.recalculate_enforcement_preview, (), 3, "enqueue_enforcement_preview"),
			(passkey_settings.count_enforcement_draft, (draft,), 20, "count_enforcement_draft"),
			(passkey_settings.get_enforcement_preview, ("0" * 16,), 30, "get_enforcement_preview"),
		):
			with self.subTest(endpoint=endpoint.__name__), patch.object(boot, operation) as action:
				for _ in range(limit):
					endpoint(*args)
				self.assertEqual(action.call_count, limit)
				with self.assertRaises(frappe.TooManyRequestsError):
					endpoint(*args)
				self.assertEqual(action.call_count, limit)

	def test_settings_preview_endpoints_refuse_non_system_managers(self):
		self._clear_preview_cache()
		sign_in(self._user())
		# v15's frappe.only_for is a no-op while flags.in_test is set.
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.flags.in_test = False
		self.addCleanup(setattr, frappe.flags, "in_test", saved_in_test)
		with patch.object(frappe, "enqueue") as enqueue:
			for endpoint, args in (
				(passkey_settings.get_settings_context, ()),
				(passkey_settings.recalculate_enforcement_preview, ()),
				(passkey_settings.count_enforcement_draft, (json.dumps(self._draft()),)),
				(passkey_settings.get_enforcement_preview, ("0" * 16,)),
			):
				with self.subTest(endpoint=endpoint.__name__), self.assertRaises(frappe.PermissionError):
					endpoint(*args)
		enqueue.assert_not_called()

	# ---- unsaved (draft) choice --------------------------------------

	def _draft(self, **overrides) -> dict:
		"""The form's enforcement inputs as passkey_settings.js sends them."""
		return {
			"passkey_rp_id": RP_ID,
			"passkey_origins": "https://example.com",
			"passkey_app_origins": "",
			"login_with_passkey": 1,
			"passkey_as_second_factor": 0,
			"passkey_enforce_scope": "All users",
			"passkey_enforce_privileged_always": 1,
			"passkey_enforce_roles": [],
			**overrides,
		}

	def _role(self, name: str, desk_access: int = 1) -> str:
		frappe.get_doc({"doctype": "Role", "role_name": name, "desk_access": desk_access}).insert(
			ignore_permissions=True
		)
		self.addCleanup(
			delete_fixture, "Role", name, force=1, ignore_permissions=True, delete_permanently=True
		)
		return name

	def test_draft_count_runs_in_the_background_and_leaves_the_saved_policy_alone(self):
		self._clear_preview_cache()
		role = self._role("Passkeys Draft Test Role")
		self._user([role])
		make_credential(self._user([role]))  # has a passkey: not counted
		self._set(passkey_enforce_scope="No one", passkey_enforce_privileged_always=0)
		sign_in("Administrator")
		draft = self._draft(
			passkey_enforce_scope="Selected roles",
			passkey_enforce_privileged_always=0,
			passkey_enforce_roles=[role],
		)
		with (
			patch.object(frappe, "enqueue") as enqueue,
			patch.object(boot, "count_users_to_enroll", wraps=boot.count_users_to_enroll) as count,
		):
			queued = passkey_settings.count_enforcement_draft(json.dumps(draft))
			count.assert_not_called()  # the request only queues
			enqueue.assert_called_once_with(
				"passkeys.boot.refresh_enforcement_preview",
				queue="short",
				enqueue_after_commit=True,
				draft=draft,
			)
			self.assertEqual(queued["after_scan"], 0)
			self.assertIsNone(passkey_settings.get_enforcement_preview(queued["signature"]))
			boot.refresh_enforcement_preview(draft=enqueue.call_args.kwargs["draft"])  # the worker
			count.assert_called_once()
		preview = passkey_settings.get_enforcement_preview(queued["signature"])
		self.assertEqual(preview["count"], 1)
		self.assertGreater(preview["scan"], queued["after_scan"])
		self.assertIsNone(boot.settings_banner_context()["enforcement_preview"])
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_scope"), "No one")

		# Saving that choice makes it the saved policy: the same signature and count.
		self._set(passkey_enforce_scope="Selected roles")
		self._set_enforced_roles(role)
		self.assertEqual(boot.settings_banner_context()["enforcement_preview"], preview)

	def test_draft_count_refuses_malformed_drafts(self):
		self._clear_preview_cache()
		sign_in("Administrator")
		draft = self._draft()
		missing = dict(draft)
		del missing["passkey_enforce_roles"]
		for value in (
			"not json",
			json.dumps(["All users"]),
			json.dumps(missing),
			json.dumps({**draft, "passkey_enforce_grace_logins": 0}),
			json.dumps({**draft, "passkey_enforce_scope": "Everyone"}),
			json.dumps({**draft, "login_with_passkey": "1"}),
			json.dumps({**draft, "passkey_rp_id": None}),
			json.dumps({**draft, "passkey_enforce_roles": "System Manager"}),
			json.dumps({**draft, "passkey_enforce_roles": [""]}),
			json.dumps({**draft, "passkey_enforce_roles": [{"role": "System Manager"}]}),
			json.dumps({**draft, "passkey_rp_id": "https://example.com"}),
		):
			with (
				self.subTest(value=value),
				patch.object(frappe, "enqueue") as enqueue,
				self.assertRaises(frappe.ValidationError),
			):
				passkey_settings.count_enforcement_draft(value)
			enqueue.assert_not_called()
		with self.assertRaises(frappe.ValidationError):
			boot.refresh_enforcement_preview(draft=missing)
		for signature in ("", "0" * 15, "A" * 16, "../" + "0" * 13):
			with self.subTest(signature=signature), self.assertRaises(frappe.ValidationError):
				passkey_settings.get_enforcement_preview(signature)
		self.assertRaises(frappe.ValidationError, boot.get_enforcement_preview, None)

	def test_draft_count_refuses_oversized_drafts(self):
		"""Each text input and the role list have a size cap, so one call stays cheap in the request,
		the job payload and the count; the largest allowed draft still counts."""
		self._clear_preview_cache()
		sign_in("Administrator")
		draft = self._draft()
		largest = {
			**draft,
			**{
				field: draft[field].ljust(boot.ENFORCEMENT_DRAFT_TEXT_MAX_LENGTH)
				for field in boot.ENFORCEMENT_DRAFT_TEXT_FIELDS
			},
			"passkey_enforce_roles": [
				str(number).rjust(frappe.db.VARCHAR_LEN, "0")
				for number in range(boot.ENFORCEMENT_DRAFT_MAX_ROLES)
			],
		}
		oversized = {
			**{
				field: {**largest, field: largest[field] + " "}
				for field in boot.ENFORCEMENT_DRAFT_TEXT_FIELDS
			},
			"one role too many": {
				**largest,
				"passkey_enforce_roles": [*largest["passkey_enforce_roles"], "Extra"],
			},
			"role name too long": {**draft, "passkey_enforce_roles": ["0" * (frappe.db.VARCHAR_LEN + 1)]},
		}
		for case, value in oversized.items():
			with self.subTest(case=case), patch.object(frappe, "enqueue") as enqueue:
				with self.assertRaises(frappe.ValidationError):
					passkey_settings.count_enforcement_draft(json.dumps(value))
				enqueue.assert_not_called()
		with patch.object(frappe, "enqueue") as enqueue:
			passkey_settings.count_enforcement_draft(json.dumps(largest))
		enqueue.assert_called_once()

	def test_daily_jobs_keep_only_the_saved_policys_count(self):
		"""Draft counts live until the next daily run, so the preview hash can't keep growing; the
		saved count and the scan numbering open forms wait on stay."""
		self._clear_preview_cache()
		drafts = [
			self._draft(passkey_enforce_scope="No one"),
			self._draft(passkey_enforce_privileged_always=0),
		]
		signatures = [boot.enforcement_preview_signature(boot.get_draft_settings(draft)) for draft in drafts]
		saved = boot.enforcement_preview_signature(frappe.get_doc("Passkey Settings"))
		self.assertNotIn(saved, signatures)
		with patch.object(boot, "count_users_to_enroll", return_value=0):
			for draft in drafts:
				boot.refresh_enforcement_preview(draft=draft)
			self.assertTrue(all(boot.get_enforcement_preview(signature) for signature in signatures))
			for method in frappe.get_hooks("scheduler_events", app_name="passkeys")["daily_long"]:
				frappe.get_attr(method)()
		name = frappe.cache.make_key(boot.ENFORCEMENT_PREVIEW_KEY)
		fields = {field.decode() for field in redis.Redis.hkeys(frappe.cache, name)}
		self.assertEqual(fields, {"epoch", "seq", f"scan:{saved}", f"result:{saved}"})
		self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["scan"], 3)
		self.assertEqual(boot.get_enforcement_preview_scan(), 3)

	def test_draft_count_reports_a_full_queue(self):
		self._clear_preview_cache()
		sign_in("Administrator")
		with (
			patch.object(frappe.local, "message_log", []),
			patch.dict(frappe.flags, {"mute_messages": False}),
			patch(
				"frappe.utils.background_jobs._check_queue_size", side_effect=self._full_preview_queue
			) as capacity,
			self.assertRaisesRegex(frappe.QueueOverloaded, "count could not start"),
		):
			passkey_settings.count_enforcement_draft(json.dumps(self._draft()))
		capacity.assert_called_once()

	def test_draft_endpoints_refuse_when_core_serves_passkeys(self):
		sign_in("Administrator")
		with patch("passkeys.install.is_core_native", return_value=True):
			for endpoint, args in (
				(passkey_settings.count_enforcement_draft, (json.dumps(self._draft()),)),
				(passkey_settings.get_enforcement_preview, ("0" * 16,)),
			):
				with self.subTest(endpoint=endpoint.__name__), self.assertRaises(PasskeyServedByCore):
					endpoint(*args)

	# ---- the set query agrees with the per-user rule -----------------

	def _users_by_rule(self, settings) -> set[str]:
		"""The per-user count this query replaced, kept as the reference."""
		enrolled = set(
			frappe.get_all("WebAuthn Credential", filters={"enabled": 1, "rp_id": RP_ID}, pluck="user")
		)
		return {
			user
			for user in frappe.get_all("User", filters={"enabled": 1}, pluck="name")
			if user != "Guest" and user not in enrolled and boot._user_in_enforce_scope(user, settings)
		}

	def test_set_query_matches_the_per_user_rule(self):
		role = self._role("Passkeys Scope Role A")
		other = self._role("Passkeys Scope Role B")
		portal = self._role("Passkeys Portal Role", desk_access=0)
		users = {
			"role": self._user([role]),
			"other": self._user([other]),
			"both": self._user([role, other]),
			"manager": self._user(["System Manager"]),
			"website": self._user(),
			"portal": self._user([portal]),
			"disabled": self._user([role]),
			"exempt": self._user([role, "System Manager"]),
			"marker_not_1": self._user([role]),
			"enrolled": self._user([role]),
			"stale": self._user([role]),
			"disabled_passkey": self._user([role]),
			"automatic_rows": self._user(),
		}
		frappe.db.set_value("User", users["disabled"], "enabled", 0)
		boot.set_exempt(users["exempt"], True)
		self.addCleanup(boot.set_exempt, users["exempt"], False)
		frappe.db.set_default(f"{users['marker_not_1']}_passkey_exempt", "0", parent=DEFAULTS_PARENT)
		self.addCleanup(boot.set_exempt, users["marker_not_1"], False)
		make_credential(users["enrolled"])
		make_credential(users["stale"], rp_id="old.example.com")
		make_credential(users["disabled_passkey"], enabled=0)
		# Rows for automatic roles count only for Administrator; get_roles drops them for others.
		for automatic in ("Desk User", "Administrator", "All"):
			frappe.get_doc(
				{
					"doctype": "Has Role",
					"parent": users["automatic_rows"],
					"parenttype": "User",
					"parentfield": "roles",
					"role": automatic,
				}
			).db_insert()
		frappe.clear_cache(user=users["automatic_rows"])
		self.assertEqual(frappe.db.get_value("User", users["portal"], "user_type"), "Website User")
		self.assertEqual(frappe.db.get_value("User", users["role"], "user_type"), "System User")

		for scope, privileged, roles in (
			("All users", 1, []),
			("All users", 0, []),
			("No one", 1, []),
			("No one", 0, []),
			("Selected roles", 0, []),
			("Selected roles", 1, []),
			("Selected roles", 0, [role]),
			("Selected roles", 1, [role, other]),
			("Selected roles", 0, [portal]),
			("Selected roles", 0, ["System Manager"]),
			("Selected roles", 0, ["All"]),
			("Selected roles", 0, ["Guest"]),
			("Selected roles", 0, ["Desk User"]),
			("Selected roles", 0, ["Administrator"]),
			("Selected roles", 0, [other, "Desk User"]),
		):
			settings = frappe.get_doc("Passkey Settings")
			settings.passkey_enforce_scope = scope
			settings.passkey_enforce_privileged_always = privileged
			settings.set("passkey_enforce_roles", [{"role": name} for name in roles])
			expected = self._users_by_rule(settings)
			query = boot.users_to_enroll_query(settings, RP_ID)
			with self.subTest(scope=scope, privileged=privileged, roles=roles):
				names = query.run(pluck=True) if query else []
				self.assertEqual((set(names), len(names)), (expected, len(expected)))
				self.assertEqual(boot.count_users_to_enroll(settings, RP_ID), len(expected))
			if (scope, roles) == ("Selected roles", [role]):
				# The seeds exercise the rule: roles, exemption, disabled users and passkeys.
				counted = {
					users[key] for key in ("role", "both", "marker_not_1", "stale", "disabled_passkey")
				}
				self.assertEqual(expected & set(users.values()), counted)

	def test_administrator_scope_uses_assigned_roles_not_every_role(self):
		# get_roles("Administrator") returns every Role, which used to put Administrator
		# in every selected role.
		self.assertTrue(self._verdict("Administrator")["in_scope"])
		self.assertFalse(enforcement_admin.admin_enforcement_view("Administrator")["exempt"])

		scope_role = "Passkeys Test Scope Role"
		if not frappe.db.exists("Role", scope_role):
			frappe.get_doc({"doctype": "Role", "role_name": scope_role}).insert(ignore_permissions=True)
		self.addCleanup(
			delete_fixture, "Role", scope_role, force=1, ignore_permissions=True, delete_permanently=True
		)
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=0)
		self._set_enforced_roles(scope_role)
		self.assertFalse(self._verdict("Administrator")["in_scope"])

		self._set(passkey_enforce_privileged_always=1)
		self.assertTrue(self._verdict("Administrator")["in_scope"])
		self.assertTrue(self._verdict(self._user(roles=["System Manager"]))["in_scope"])

	def test_selected_implicit_roles_match_ordinary_users(self):
		# Frappe grants All (and Desk User on newer versions) without a Has Role row.
		user = self._user()
		self._set(passkey_enforce_scope="Selected roles", passkey_enforce_privileged_always=0)
		for role in ("All", "Desk User"):
			if role not in frappe.get_roles(user):
				continue
			with self.subTest(role=role):
				self._set_enforced_roles(role)
				self.assertTrue(self._verdict(user)["in_scope"])

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

	def test_stale_only_enforcement_and_admin_counts_require_enrollment(self):
		user = self._user()
		make_credential(user, rp_id="old.example.com")
		sign_in("Administrator")
		status = enforcement_admin.get_user_enforcement_admin(user)
		self.assertEqual(status["credential_count"], 0)
		self.assertEqual(boot.build_passkeys_boot(user)["credential_count"], 0)
		make_credential(user)
		self.assertEqual(enforcement_admin.get_user_enforcement_admin(user)["credential_count"], 1)

	def test_preview_off_is_zero_and_rp_changes_signature(self):
		self._clear_preview_cache()
		self._user()
		before = boot.enforcement_preview_signature(self._settings())
		original = frappe.db.get_single_value("Passkey Settings", "passkey_app_origins")
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", "passkey_app_origins", original)
		frappe.db.set_single_value("Passkey Settings", "passkey_app_origins", "")
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "outside.test")
		flush_settings_cache()
		with patch.dict(frappe.conf, {"host_name": "https://example.com"}):
			self.assertEqual(boot.effective_rung("Administrator", self._settings()), "off")
			self.assertNotEqual(boot.enforcement_preview_signature(self._settings()), before)
			boot.refresh_enforcement_preview()
			self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["count"], 0)

	def test_preview_counts_stale_only_users_as_unenrolled(self):
		self._clear_preview_cache()
		user = self._user()
		cred = make_credential(user)
		boot.refresh_enforcement_preview()
		before = boot.settings_banner_context()["enforcement_preview"]["count"]
		frappe.db.set_value(cred.doctype, cred.name, "rp_id", "old.example.com")
		boot.refresh_enforcement_preview()
		self.assertEqual(boot.settings_banner_context()["enforcement_preview"]["count"], before + 1)
