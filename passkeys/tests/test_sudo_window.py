# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sudo-window semantics on the live bench:
seeding at ``on_session_creation`` classified by login method; TTL honesty;
the management-sudo check helper; and the passkey-grant-only guard on
``set_passkey_only_login``."""

import hashlib
import time

import frappe

from passkeys import session, state
from passkeys.passkey import PasskeyConfirmationRequired
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user


class SudoWindowTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")
		self._reset_login_signals()
		self.addCleanup(self._reset_login_signals)

	@property
	def sid(self) -> str:
		# frappe.set_user() sets session.sid = username, so read it live (never
		# cache it across a set_user).
		return frappe.session.sid

	def _clear(self, sid):
		state.clear_sudo_window(sid)

	def _reset_login_signals(self):
		frappe.local.flags.pop("passkey_login", None)
		frappe.local.form_dict.pop("cmd", None)
		frappe.local.form_dict.pop(session.GRANT_KWARG, None)

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	# ---- seeding at on_session_creation ----------------------------

	def test_passkey_login_seeds_full_sudo(self):
		user = self._user()
		frappe.set_user(user)
		frappe.local.flags.passkey_login = 1
		session.seed_sudo_window()
		window = session.get_window(user, self.sid)
		self.assertIsNotNone(window)
		self.assertEqual(window["seeded_by"], "passkey")
		self.assertTrue(session.has_management_sudo(user, self.sid))

	def test_password_login_seeds_full_sudo(self):
		user = self._user()
		frappe.set_user(user)
		frappe.local.form_dict["cmd"] = "login"  # v15/v16 core login trigger
		session.seed_sudo_window()
		window = session.get_window(user, self.sid)
		self.assertEqual(window["seeded_by"], "password")
		self.assertTrue(session.has_management_sudo(user, self.sid))

	def test_weak_login_seeds_restricted_window(self):
		user = self._user()
		frappe.set_user(user)
		# no passkey flag, no cmd=login → email-link/OAuth-class weak login
		session.seed_sudo_window()
		window = session.get_window(user, self.sid)
		self.assertEqual(window["seeded_by"], "weak")
		# a weak window never satisfies management
		self.assertFalse(session.has_management_sudo(user, self.sid))

	def test_guest_session_seeds_nothing(self):
		# frappe.session.user is Administrator here; simulate Guest explicitly
		frappe.set_user("Guest")
		session.seed_sudo_window()
		self.assertIsNone(state.get_sudo_window(frappe.session.sid))

	def test_password_login_by_passkey_holder_risk_event_gated_by_knob(self):
		"""C10: a password-seeded window for a user holding an enabled
		passkey records the ``password_login_by_passkey_holder`` risk event — but only
		when the opt-in ``passkey_notify_password_login`` knob is on (default OFF ⇒ no
		telemetry, and the enabled-credential read never touches the hot login path)."""
		user = self._user()
		make_credential(user)  # ≥1 enabled credential
		frappe.set_user(user)
		self.addCleanup(flush_settings_cache)
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", "passkey_notify_password_login", 0)

		def seed_as_password():
			frappe.local.form_dict["cmd"] = "login"  # classify the window as password
			session.seed_sudo_window()

		# knob OFF (default) → nothing recorded
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_password_login", 0)
		flush_settings_cache()
		before = frappe.db.count("Activity Log", {"user": user})
		seed_as_password()
		self.assertEqual(frappe.db.count("Activity Log", {"user": user}), before)

		# knob ON → the risk event is recorded
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_password_login", 1)
		flush_settings_cache()
		seed_as_password()
		contents = set(frappe.get_all("Activity Log", filters={"user": user}, pluck="content"))
		self.assertIn("passkeys:password_login_by_passkey_holder", contents)

	# ---- TTL honesty (Redis ex is the sole expiry authority) -------

	def test_seed_ttl_is_bounded_by_settings_window(self):
		user = self._user()
		frappe.set_user(user)
		frappe.local.flags.passkey_login = 1
		session.seed_sudo_window()
		window_s = frappe.db.get_single_value("Passkey Settings", "passkey_reauth_window") or 600
		pttl_ms = frappe.cache.pttl(state._make_key(state.SUDO_PREFIX + self.sid))
		self.assertGreater(pttl_ms, 0)
		self.assertLessEqual(pttl_ms, int(window_s) * 1000)

	def test_window_expires_when_ttl_elapses(self):
		user = self._user()
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=1)
		self.assertIsNotNone(session.get_window(user, self.sid))
		time.sleep(1.2)
		self.assertIsNone(session.get_window(user, self.sid))

	# ---- check helper ----------------------------------------------

	def test_management_sudo_accepts_full_refuses_weak_and_foreign(self):
		user = self._user()
		other = self._user()
		for method in session.FULL_SUDO_METHODS:
			state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": method}, ttl=600)
			self.assertTrue(session.has_management_sudo(user, self.sid), method)
		# weak-seeded window is refused
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "weak"}, ttl=600)
		self.assertFalse(session.has_management_sudo(user, self.sid))
		# a window belonging to another user is refused (no cross-user reuse)
		state.set_sudo_window(self.sid, {"v": 1, "user": other, "seeded_by": "password"}, ttl=600)
		self.assertFalse(session.has_management_sudo(user, self.sid))
		# no window at all
		state.clear_sudo_window(self.sid)
		self.assertFalse(session.has_management_sudo(user, self.sid))

	def test_require_management_sudo_raises_typed_error(self):
		user = self._user()
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)
		with self.assertRaises(PasskeyConfirmationRequired):
			session.require_management_sudo(user)
		self.assertEqual(frappe.local.response.get("action"), session.MANAGE_ACTION)
		self.assertIn("sudo", frappe.local.response.get("methods"))

	# ---- passkey-grant consumer -------------------------

	def _seed_grant(self, user, action, params, method="passkey"):
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": frappe.session.sid,
				"action": action,
				"method": method,
				"payload_hash": session.payload_hash(params),
			},
		)
		frappe.local.form_dict[session.GRANT_KWARG] = token
		return token

	def test_passkey_grant_consumed_once(self):
		user = self._user()
		frappe.set_user(user)
		params = {"enabled": True}
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, params)
		self.assertTrue(session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, params))
		# single-use: a replay of the same token finds nothing
		self.assertFalse(session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, params))

	def test_password_minted_grant_refused(self):
		user = self._user()
		frappe.set_user(user)
		params = {"enabled": True}
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, params, method="password")
		# a password-minted grant never satisfies the passkey-only gate
		self.assertFalse(session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, params))

	def test_grant_payload_and_action_are_bound(self):
		user = self._user()
		frappe.set_user(user)
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": True})
		# wrong payload (enable vs disable) is rejected
		self.assertFalse(
			session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": False})
		)
