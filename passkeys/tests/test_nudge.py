# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Enrollment-nudge cadence machinery:
server-side per-user counters (cap + cooldown + opt-out), the ``record_nudge``
event vocabulary, and the eligibility gate the boot flag / portal expose."""

from unittest.mock import patch

import frappe
from frappe.utils import add_to_date, now_datetime

from passkeys import boot, notifications, passkey
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_handle, make_user, sign_in

_NUDGE_KNOBS = (
	"passkey_enforce_scope",
	"passkey_enforce_privileged_always",
	"passkey_everyone_else",
	"passkey_nudge_max_prompts",
	"passkey_nudge_cooldown_days",
	"login_with_passkey",
)


class NudgeCadenceTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_enforce_scope = "No one"
		settings.passkey_enforce_privileged_always = 0
		settings.passkey_everyone_else = "Nudge"
		settings.passkey_nudge_max_prompts = 3
		settings.passkey_nudge_cooldown_days = 30
		settings.save(ignore_permissions=True)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		sign_in("Administrator")
		for field in _NUDGE_KNOBS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		flush_settings_cache()

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"}
		)
		return user

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	# ---- eligibility gate -------------------------------------------------

	def test_fresh_state_zero_credentials_is_eligible(self):
		user = self._user()
		self.assertTrue(boot.nudge_eligible(user, self._settings(), 0))

	def test_non_mapping_nudge_state_falls_back_to_zero(self):
		user = self._user()
		for raw in ("null", "[]", "1"):
			with self.subTest(raw=raw):
				frappe.db.set_default(f"{user}_passkey_nudge", raw, parent=DEFAULTS_PARENT)
				self.assertEqual(
					boot.get_nudge_state(user),
					{"declines": 0, "last_shown": None, "opt_out": 0},
				)

	def test_not_eligible_when_user_already_has_a_credential(self):
		user = self._user()
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 1))

	def test_policy_off_disables_the_nudge(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_everyone_else", "Off")
		flush_settings_cache()
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	def test_enforce_policy_suppresses_the_nudge_cadence(self):
		"""Under an enforcement rung the nudge cadence stands down — the enforcement
		interstitial owns the surface, not the dismissible nudge."""
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_enforce_scope", "All users")
		flush_settings_cache()
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	# ---- cap (max_prompts, knob-referenced) ----------------------

	def test_cap_reached_after_max_prompts_shown(self):
		user = self._user()
		for _ in range(3):
			boot.record_nudge_event(user, "shown")
		state = boot.get_nudge_state(user)
		self.assertEqual(state["declines"], 3)
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0, state))

	def test_lowering_the_cap_knob_takes_effect(self):
		user = self._user()
		boot.record_nudge_event(user, "shown")  # declines == 1
		frappe.db.set_single_value("Passkey Settings", "passkey_nudge_max_prompts", 1)
		flush_settings_cache()
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	# ---- cooldown (cooldown_days, knob-referenced) ---------------

	def test_cooldown_blocks_within_the_window(self):
		user = self._user()
		boot.record_nudge_event(user, "shown")  # last_shown == now
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	def test_cooldown_elapsed_re_enables(self):
		user = self._user()
		old = add_to_date(now_datetime(), days=-31).isoformat()
		frappe.db.set_default(
			f"{user}_passkey_nudge",
			frappe.as_json({"declines": 1, "last_shown": old, "opt_out": 0}),
			parent=DEFAULTS_PARENT,
		)
		self.assertTrue(boot.nudge_eligible(user, self._settings(), 0))

	# ---- opt-out ----------------------------------------------------------

	def test_opt_out_is_terminal(self):
		user = self._user()
		boot.record_nudge_event(user, "opt_out")
		self.assertEqual(boot.get_nudge_state(user)["opt_out"], 1)
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	# ---- record_nudge event semantics -------------------------------------

	def test_declined_refreshes_cooldown_without_advancing_cap(self):
		user = self._user()
		boot.record_nudge_event(user, "declined")
		state = boot.get_nudge_state(user)
		self.assertEqual(state["declines"], 0)  # `shown` is the counter, not `declined`
		self.assertIsNotNone(state["last_shown"])

	def test_record_nudge_endpoint_folds_state(self):
		user = self._user()
		sign_in(user)
		result = passkey.record_nudge("shown")
		self.assertEqual(result["nudge_state"]["declines"], 1)

	def test_record_nudge_rejects_unknown_event(self):
		user = self._user()
		sign_in(user)
		with self.assertRaises(frappe.ValidationError):
			passkey.record_nudge("bogus")

	def test_record_nudge_requires_auth(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.AuthenticationError):
			passkey.record_nudge("shown")

	def test_shown_preserves_opt_out_from_current_database_row(self):
		user = self._user()
		boot.record_nudge_event(user, "shown")
		self.assertEqual(boot.get_nudge_state(user)["opt_out"], 0)
		frappe.db.set_value(
			"DefaultValue",
			{"parent": DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"},
			"defvalue",
			frappe.as_json({"declines": 2, "opt_out": 1, "last_shown": None}),
		)
		result = boot.record_nudge_event(user, "shown")
		self.assertEqual(result["opt_out"], 1)
		self.assertEqual(result["declines"], 3)
		self.assertEqual(boot.get_nudge_state(user), result)

	def _seed_state(self, user, marker="marker"):
		boot.record_nudge_event(user, "opt_out")
		boot.record_enforcement_defer(user)
		frappe.db.set_default(notifications.incapable_notify_key(user), marker, parent=DEFAULTS_PARENT)
		return self._state(user)

	def _state(self, user):
		return [boot.get_default_value(key) for key in boot.get_user_state_keys(user)]

	def test_user_rename_moves_all_default_state(self):
		old = self._user()
		new = f"renamed-{old}"
		self.addCleanup(frappe.delete_doc, "User", new, force=1, ignore_permissions=True)
		expected = self._seed_state(old)
		frappe.rename_doc("User", old, new)
		self.assertEqual(self._state(new), expected)
		self.assertEqual(self._state(old), [None, None, None])

	def test_case_only_user_rename_keeps_default_state(self):
		# utf8mb4_unicode_ci matches both spellings to one row, so a copy-then-delete
		# rename would delete the state it meant to carry.
		old = self._user()
		new = old.capitalize()
		expected = self._seed_state(old)
		frappe.rename_doc("User", old, new)
		self.assertEqual(frappe.db.get_value("User", new, "name"), new)
		self.assertEqual(self._state(new), expected)
		self.assertEqual(
			frappe.get_all(
				"DefaultValue",
				filters={"parent": DEFAULTS_PARENT, "defkey": ("in", boot.get_user_state_keys(new))},
				pluck="defkey",
				order_by="defkey",
			),
			sorted(boot.get_user_state_keys(new)),
		)

	def test_user_merge_preserves_target_default_state(self):
		old, new = self._user(), self._user()
		self._seed_state(old, marker=old)
		boot.record_nudge_event(new, "shown")
		boot.record_enforcement_defer(new)
		boot.record_enforcement_defer(new)
		frappe.db.set_default(notifications.incapable_notify_key(new), new, parent=DEFAULTS_PARENT)
		expected = self._state(new)
		frappe.rename_doc("User", old, new, merge=True)
		self.assertEqual(self._state(new), expected)
		self.assertEqual(self._state(old), [None, None, None])

	def test_user_merge_carries_state_when_target_has_none(self):
		old, new = self._user(), self._user()
		expected = self._seed_state(old)
		frappe.rename_doc("User", old, new, merge=True)
		self.assertEqual(self._state(new), expected)
		self.assertEqual(self._state(old), [None, None, None])

	def test_merging_two_enrolled_users_is_refused_clearly(self):
		old, new = self._user(), self._user()
		make_handle(old)
		make_handle(new)
		with self.assertRaisesRegex(frappe.ValidationError, "both users have passkeys"):
			frappe.rename_doc("User", old, new, merge=True)
		self.assertTrue(frappe.db.exists("User", old))
		self.assertEqual(frappe.db.count("WebAuthn User Handle", {"user": ("in", [old, new])}), 2)

	def test_state_reads_never_fall_back_to_a_scrubbed_key(self):
		# frappe.db.get_default falls back to scrub(key): "mary-jane@x" would read
		# "mary_jane@x"'s row.
		hyphen = f"mary-jane-{frappe.generate_hash(length=6)}@example.com"
		underscore = hyphen.replace("-", "_")
		for key, value in (
			(f"{underscore}_passkey_nudge", '{"declines": 0, "opt_out": 1}'),
			(f"{underscore}_passkey_enforce", '{"grace_used": 5}'),
		):
			frappe.db.set_default(key, value, parent=DEFAULTS_PARENT)
			self.addCleanup(frappe.db.delete, "DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": key})
		self.assertEqual(boot.get_nudge_state(hyphen)["opt_out"], 0)
		self.assertEqual(boot.get_enforcement_state(hyphen)["grace_used"], 0)

	def test_dormant_rename_leaves_defaults_untouched(self):
		old, new = self._user(), self._user()
		boot.record_nudge_event(old, "opt_out")
		with patch.object(passkey.install, "dormant", return_value=True):
			passkey.rename_user_artifacts(frappe.get_doc("User", new), "after_rename", old, new)
		self.assertEqual(boot.get_nudge_state(old)["opt_out"], 1)
		self.assertEqual(boot.get_nudge_state(new)["opt_out"], 0)
