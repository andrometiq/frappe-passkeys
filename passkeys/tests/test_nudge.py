# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Enrollment-nudge cadence machinery:
server-side per-user counters (cap + cooldown + opt-out), the ``record_nudge``
event vocabulary, and the eligibility gate the boot flag / portal expose."""

import frappe
from frappe.utils import add_to_date, now_datetime

from passkeys import boot, passkey
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user

_NUDGE_KNOBS = ("passkey_enrollment_nudge", "passkey_nudge_max_prompts", "passkey_nudge_cooldown_days")


class NudgeCadenceTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_enrollment_nudge = 1
		settings.passkey_nudge_max_prompts = 3
		settings.passkey_nudge_cooldown_days = 30
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		for field in _NUDGE_KNOBS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

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

	def test_not_eligible_when_user_already_has_a_credential(self):
		user = self._user()
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 1))

	def test_knob_off_disables_the_nudge(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_enrollment_nudge", 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
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
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
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
		frappe.set_user(user)
		result = passkey.record_nudge("shown")
		self.assertEqual(result["nudge_state"]["declines"], 1)

	def test_record_nudge_rejects_unknown_event(self):
		user = self._user()
		frappe.set_user(user)
		with self.assertRaises(frappe.ValidationError):
			passkey.record_nudge("bogus")

	def test_record_nudge_requires_auth(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.AuthenticationError):
			passkey.record_nudge("shown")
