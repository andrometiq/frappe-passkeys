# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Phase-6 management server behaviors on the live bench: out-of-band
notifications, risk-event telemetry, the admin
lockout interlock, and the row-7 reauth refusal under
``disable_user_pass_login``."""

import base64
import functools
import hashlib
import itertools
import json
import pickle
import time
import types
from unittest.mock import call, patch

import frappe
import redis
from frappe.auth import CookieManager, LoginManager
from frappe.utils import CallbackManager, set_request
from frappe.utils.password import set_encrypted_password
from frappe.utils.response import make_logs

from passkeys import ceremony, confirm, notifications, session, state
from passkeys.api import credentials
from passkeys.session import (
	drop_ended_session,
	drop_session_if_ended,
	end_sessions,
	get_stored_session_id,
	refuse_ended_session,
)
from passkeys.tests.committed_state import delete_fixture
from passkeys.tests.compat import (
	IntegrationTestCase,
	PinnedSiteRp,
	activity_log_count,
	arrange_mode_floor,
	bust_system_settings_cache,
	flush_settings_cache,
)
from passkeys.tests.factories import make_credential, make_handle, make_user, sign_in

PWD = "Secret_passw0rd_9x!"


class _Base(PinnedSiteRp, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(
			lambda u=user: (
				frappe.db.exists("User", u)
				and delete_fixture("User", u, force=1, ignore_permissions=True, delete_permanently=True)
			)
		)
		return user


class NotificationTest(_Base):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_on_change", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_password_fallback", 1)
		flush_settings_cache()
		self.sent = []
		self._orig_sendmail = frappe.sendmail
		frappe.sendmail = lambda **kw: self.sent.append(kw)
		self.addCleanup(setattr, frappe, "sendmail", self._orig_sendmail)
		self.addCleanup(self._restore)

	def _restore(self):
		sign_in("Administrator")
		for field in ("passkey_notify_on_change", "passkey_notify_password_fallback"):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		flush_settings_cache()

	def _subjects(self):
		return " ".join(m["subject"].lower() for m in self.sent)

	def _open_at(self, host_name):
		self.addCleanup(setattr, frappe.conf, "host_name", frappe.conf.get("host_name"))
		frappe.conf.host_name = host_name

	def test_added_email_sent_when_knob_on(self):
		user = self._user()
		self._open_at("https://erp.example.com")
		notifications.notify_credential_added(user, "Phone", ip="203.0.113.7")
		self.assertEqual(len(self.sent), 1)
		self.assertIn(user, self.sent[0]["recipients"])
		self.assertIn("added", self.sent[0]["subject"].lower())
		self.assertEqual(
			self.sent[0]["message"],
			"A new passkey “Phone” was just added to your account on erp.example.com (from IP 203.0.113.7)."
			" If this wasn't you, remove it on your My Passkeys page"
			' (<a href="https://erp.example.com/passkeys">https://erp.example.com/passkeys</a>)'
			" and change your password immediately.",
		)

	def test_conditional_create_added_email_says_the_browser_saved_it(self):
		user = self._user()
		self._open_at("https://erp.example.com")
		notifications.notify_credential_added(user, "Phone", ip="203.0.113.7", is_conditional_create=True)
		self.assertIn("added", self.sent[0]["subject"].lower())
		self.assertEqual(
			self.sent[0]["message"],
			"Your browser saved a passkey “Phone” for your account on erp.example.com (from IP 203.0.113.7)"
			" after you signed in with your password. Next time you can sign in with it. If you"
			" didn't just sign in, remove it on your My Passkeys page"
			' (<a href="https://erp.example.com/passkeys">https://erp.example.com/passkeys</a>)'
			" and change your password.",
		)

	def test_change_emails_name_the_passkeys_page_in_words_without_host_name(self):
		user = self._user()
		self._open_at(None)
		site = frappe.local.site
		# Never a link built from the request's Host header.
		with patch("frappe.utils.data.get_host_name_from_request", return_value="attacker.example"):
			notifications.notify_credential_added(user, "Phone", ip="203.0.113.7")
			notifications.notify_credential_added(user, "Phone", is_conditional_create=True)
			notifications.notify_credential_flagged(user, "Phone", "sign_count_regression")
		self.assertEqual(
			[mail["message"] for mail in self.sent],
			[
				f"A new passkey “Phone” was just added to your account on {site} (from IP 203.0.113.7)."
				" If this wasn't you, remove it on your My Passkeys page and change your password"
				" immediately.",
				f"Your browser saved a passkey “Phone” for your account on {site} after you signed in"
				" with your password. Next time you can sign in with it. If you didn't just sign"
				" in, remove it on your My Passkeys page and change your password.",
				f"Your passkey “Phone” was flagged after a sign-in on {site}: it may have been copied."
				" If you don't recognize a recent sign-in, remove this passkey on your My Passkeys page"
				" and contact your administrator.",
			],
		)

	def test_added_email_escapes_the_ip(self):
		for is_conditional_create in (False, True):
			notifications.notify_credential_added(
				self._user(),
				"Phone",
				ip='<div style="display:none">',
				is_conditional_create=is_conditional_create,
			)
			self.assertIn("(from IP &lt;div style=&quot;display:none&quot;&gt;)", self.sent[-1]["message"])
			self.assertNotIn("<div", self.sent[-1]["message"])

	def test_no_email_when_notify_knob_off_but_activity_still_logged(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_on_change", 0)
		flush_settings_cache()
		before = activity_log_count({"user": user})
		notifications.notify_credential_added(user, "Phone")
		self.assertEqual(self.sent, [])
		self.assertEqual(activity_log_count({"user": user}), before + 1)

	def test_removed_email_on_endpoint_delete(self):
		user = self._user()
		self._open_at("https://erp.example.com")
		make_credential(user)
		drop = make_credential(user)
		sign_in(user)
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		self.sent.clear()
		credentials.delete_credential(drop.name)
		self.assertIn("removed", self._subjects())
		self.assertEqual(
			self.sent[0]["message"],
			"The passkey “Test Passkey” was removed from your account on erp.example.com and no longer"
			" works there. If your phone, computer or password manager still lists it, delete it there"
			" too. If you didn't expect this, contact your administrator.",
		)

	def test_change_emails_escape_the_label(self):
		user, label = self._user(), "Desk & <spare>"
		notifications.notify_credential_added(user, label)
		notifications.notify_credential_added(user, label, is_conditional_create=True)
		notifications.notify_credential_removed(user, label, by_owner=True)
		notifications.notify_credential_disabled(user, label)
		notifications.notify_credential_flagged(user, label, "sign_count_regression")
		self.assertEqual(len(self.sent), 5)
		for mail in self.sent:
			self.assertIn("Desk &amp; &lt;spare&gt;", mail["message"])
			self.assertNotIn("<spare>", mail["message"])

	def test_change_emails_name_the_address_users_open(self):
		user = self._user()
		self._open_at("https://erp.example.com")
		notifications.notify_credential_disabled(user, "Phone")
		self.assertIn(" on erp.example.com.", self.sent[-1]["message"])
		# Without host_name, the site name; never the request's Host header.
		frappe.conf.host_name = None
		with patch("frappe.utils.data.get_host_name_from_request", return_value="attacker.example"):
			notifications.notify_credential_disabled(user, "Phone")
		self.assertIn(f" on {frappe.local.site}.", self.sent[-1]["message"])

	def test_change_emails_read_a_host_name_with_a_trailing_slash(self):
		self._open_at("https://erp.example.com/")
		notifications.notify_credential_added(self._user(), "Phone")
		self.assertEqual(
			self.sent[0]["message"],
			"A new passkey “Phone” was just added to your account on erp.example.com."
			" If this wasn't you, remove it on your My Passkeys page"
			' (<a href="https://erp.example.com/passkeys">https://erp.example.com/passkeys</a>)'
			" and change your password immediately.",
		)

	def test_flagged_email_sent_once_on_sign_count_regression(self):
		user = self._user()
		self._open_at("https://erp.example.com")
		cred = make_credential(user, sign_count=10, flagged=0)
		result = types.SimpleNamespace(
			new_sign_count=5,
			sign_count_to_store=10,
			backup_state=False,
			sign_count_regression=True,
		)
		ceremony.advance_credential(cred.name, result)
		flagged_mails = [m for m in self.sent if "flag" in m["subject"].lower()]
		self.assertEqual(len(flagged_mails), 1)
		self.assertEqual(
			flagged_mails[0]["message"],
			"Your passkey “Test Passkey” was flagged after a sign-in on erp.example.com: it may have"
			" been copied. If you don't recognize a recent sign-in, remove this passkey on your My"
			' Passkeys page (<a href="https://erp.example.com/passkeys">https://erp.example.com/passkeys</a>)'
			" and contact your administrator.",
		)
		# a second regressed assertion must NOT re-spam (already flagged)
		ceremony.advance_credential(cred.name, result)
		self.assertEqual(len([m for m in self.sent if "flag" in m["subject"].lower()]), 1)

	def test_flagged_email_names_an_unlabelled_passkey_by_its_id(self):
		cred = make_credential(self._user(), sign_count=10, flagged=0)
		frappe.db.set_value("WebAuthn Credential", cred.name, "label", None, update_modified=False)
		result = types.SimpleNamespace(
			new_sign_count=5, sign_count_to_store=10, backup_state=False, sign_count_regression=True
		)
		ceremony.advance_credential(cred.name, result)
		message = next(m["message"] for m in self.sent if "flag" in m["subject"].lower())
		self.assertIn(f"“{cred.name}”", message)
		self.assertNotIn("None", message)

	def test_fallback_risk_event_emails_under_its_own_knob(self):
		user = self._user()
		notifications.record_risk_event(notifications.RISK_FALLBACK_USED, user, "otp fallback")
		self.assertEqual(len(self.sent), 1)  # passkey_notify_password_fallback == 1

	def test_fallback_risk_event_silent_when_knob_off(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_password_fallback", 0)
		flush_settings_cache()
		before = activity_log_count({"user": user})
		notifications.record_risk_event(notifications.RISK_FALLBACK_USED, user, "otp fallback")
		self.assertEqual(self.sent, [])
		self.assertEqual(activity_log_count({"user": user}), before + 1)

	def test_change_email_survives_activity_log_failure(self):
		user = self._user()
		with (
			patch.object(notifications, "_activity_log", side_effect=RuntimeError("audit down")),
			patch("frappe.log_error"),
		):
			notifications.notify_credential_added(user, "Phone")
		self.assertEqual(len(self.sent), 1)

	def test_risk_email_survives_activity_log_failure(self):
		user = self._user()
		with (
			patch.object(notifications, "_activity_log", side_effect=RuntimeError("audit down")),
			patch("frappe.log_error"),
		):
			notifications.record_risk_event(notifications.RISK_FALLBACK_USED, user, "otp fallback")
		self.assertEqual(len(self.sent), 1)

	def test_enforcement_email_survives_audit_failure_and_excludes_reporter(self):
		user = self._user()
		with (
			patch.object(notifications, "_activity_log", side_effect=RuntimeError("audit down")),
			patch(
				"frappe.utils.user.get_system_managers",
				return_value=[user, "manager@example.com", "Administrator"],
			) as get_managers,
			patch("frappe.log_error"),
		):
			notifications.record_enforcement_incapable(user)
		get_managers.assert_called_once_with(only_name=True)
		self.assertEqual(self.sent[0]["recipients"], ["manager@example.com"])


class AdminInterlockTest(_Base):
	"""Lockout interlock: a System Manager cannot disable/delete the last
	enabled credential of a passkey-only user; owner notice is still sent; the
	User-delete cascade is never blocked by it."""

	def setUp(self):
		super().setUp()
		arrange_mode_floor(self)  # mode floor for the flagged handles this interlock battery creates
		self.sent = []
		self._orig_sendmail = frappe.sendmail
		frappe.sendmail = lambda **kw: self.sent.append(kw)
		self.addCleanup(setattr, frappe, "sendmail", self._orig_sendmail)

	def test_admin_delete_last_credential_of_passkey_only_user_blocked(self):
		user = self._user()
		cred = make_credential(user)
		make_handle(user, passkey_only_login=1)
		sign_in("Administrator")
		with self.assertRaises(frappe.ValidationError):
			frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
		self.assertTrue(frappe.db.exists("WebAuthn Credential", cred.name))

	def test_admin_disable_last_credential_of_passkey_only_user_blocked(self):
		user = self._user()
		cred = make_credential(user)
		make_handle(user, passkey_only_login=1)
		doc = frappe.get_doc("WebAuthn Credential", cred.name)
		doc.enabled = 0
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)

	def test_admin_disable_non_last_credential_notifies_owner(self):
		user = self._user()
		make_credential(user)
		drop = make_credential(user)
		make_handle(user, passkey_only_login=1)
		doc = frappe.get_doc("WebAuthn Credential", drop.name)
		doc.enabled = 0
		doc.save(ignore_permissions=True)  # another enabled survives ⇒ allowed
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", drop.name, "enabled"), 0)
		self.assertTrue(any("disabled" in m["subject"].lower() for m in self.sent))

	def test_user_delete_cascade_is_not_blocked_by_the_interlock(self):
		user = make_user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)
		# the User on_trash cascade uses raw db.delete — must NOT trip the
		# last-credential interlock, or a passkey-only user could never be deleted.
		frappe.delete_doc("User", user, force=1, ignore_permissions=True)
		self.assertFalse(frappe.db.exists("User", user))
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": user}))


class RevocationSignOutTest(_Base):
	"""Someone else disabling or deleting a passkey ends every session of its owner; the
	actor keeps theirs. The owner revoking their own passkey ends their other sessions."""

	def setUp(self):
		super().setUp()
		notify = frappe.db.get_single_value("Passkey Settings", "passkey_notify_on_change")
		self.addCleanup(flush_settings_cache)
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", "passkey_notify_on_change", notify)
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_on_change", 1)
		flush_settings_cache()
		self.addCleanup(setattr, frappe.conf, "host_name", frappe.conf.get("host_name"))
		frappe.conf.host_name = "https://erp.example.com"
		self.sent = []
		self.addCleanup(setattr, frappe, "sendmail", frappe.sendmail)
		frappe.sendmail = lambda **kw: self.sent.append(kw)
		# Cleanups run LIFO: back to Administrator, then each user delete ends that user's sessions
		# through the login manager, then the login manager is restored.
		self.addCleanup(setattr, frappe.local, "login_manager", getattr(frappe.local, "login_manager", None))
		self.owner, self.actor = self._user(), self._user()
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self._delete_new_ended_marks, self._ended_marks())

	def _ended_marks(self) -> dict[bytes, bytes]:
		return redis.Redis.hgetall(frappe.cache, frappe.cache.make_key(state.ENDED_SESSIONS))

	def _delete_new_ended_marks(self, before: dict[bytes, bytes]) -> None:
		if added := set(self._ended_marks()) - set(before):
			redis.Redis.hdel(frappe.cache, frappe.cache.make_key(state.ENDED_SESSIONS), *added)

	def _sign_in_for_real(self, user: str) -> None:
		"""A real session row, as a browser sign-in makes; the current session becomes it."""
		set_request(method="POST", path="/api/method/frappe.client.save")  # not the login path
		frappe.local.cookie_manager = CookieManager()
		frappe.local.form_dict = frappe._dict()
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as(user)

	def _sessions(self, user: str) -> int:
		return frappe.db.count("Sessions", {"user": user})

	def _two_owner_sessions_then_actor(self) -> None:
		self._sign_in_for_real(self.owner)
		self._sign_in_for_real(self.owner)
		self._sign_in_for_real(self.actor)
		self.assertEqual((self._sessions(self.owner), self._sessions(self.actor)), (2, 1))

	def _assert_nothing_reported(self, messages: list) -> None:
		"""No warning, risk event or System Manager email for an incomplete sign-out."""
		self.assertFalse([message for message in messages if "may still be signed in" in message.message])
		risk = {"user": self.owner, "content": f"passkeys:{notifications.RISK_SIGN_OUT_INCOMPLETE}"}
		self.assertEqual(activity_log_count(risk), 0)
		self.assertEqual([mail["recipients"] for mail in self.sent], [[self.owner]])

	def test_someone_elses_disable_signs_the_owner_out_everywhere(self):
		cred = make_credential(self.owner)
		self._two_owner_sessions_then_actor()
		doc = frappe.get_doc("WebAuthn Credential", cred.name)
		doc.enabled = 0
		with patch.object(frappe.local, "message_log", []):
			doc.save(ignore_permissions=True)
			self._assert_nothing_reported(frappe.local.message_log)
		self.assertEqual((self._sessions(self.owner), self._sessions(self.actor)), (0, 1))
		self.assertEqual(frappe.session.user, self.actor)
		self.assertEqual(
			self.sent[-1]["message"],
			"The passkey “Test Passkey” on your account was disabled by an administrator on"
			" erp.example.com. You can no longer sign in with it. You may need to sign in again."
			" Contact your administrator if this was unexpected.",
		)

	def test_someone_elses_delete_signs_the_owner_out_everywhere(self):
		cred = make_credential(self.owner)
		self._two_owner_sessions_then_actor()
		with patch.object(frappe.local, "message_log", []):
			frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
			self._assert_nothing_reported(frappe.local.message_log)
		self.assertEqual((self._sessions(self.owner), self._sessions(self.actor)), (0, 1))
		self.assertEqual(frappe.session.user, self.actor)
		self.assertEqual(
			self.sent[-1]["message"],
			"An administrator removed the passkey “Test Passkey” from your account on erp.example.com."
			" It no longer works there. You may need to sign in again. If your phone, computer or"
			" password manager still lists it, delete it there too. If you didn't expect this, contact"
			" your administrator.",
		)

	def _sign_in_on_another_connection(self, user: str) -> None:
		"""A sign-in committed by another request, as a login holding the credential lock does
		while the revoking request waits for it."""
		sid = frappe.generate_hash()
		conf = frappe.conf
		other = frappe.database.get_db(
			host=conf.db_host,
			port=conf.db_port,
			user=conf.db_user or conf.db_name,
			password=conf.db_password,
			cur_db_name=conf.db_name,
		)
		try:
			other.sql(
				"insert into tabSessions (sid, user, sessiondata, lastupdate, status) values (%s, %s, %s, %s, %s)",
				(sid, user, "{}", frappe.utils.now(), "Active"),
			)
			other.commit()
		finally:
			other.close()
		self.addCleanup(frappe.db.commit)
		self.addCleanup(frappe.db.sql, "delete from tabSessions where sid=%s", sid)

	def test_a_sign_in_committed_after_the_revoking_request_began_is_ended_too(self):
		for action in ("disable", "delete"):
			with self.subTest(action=action):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.actor)
				frappe.db.sql("select count(*) from tabSessions")  # the revoking request's first read
				self._sign_in_on_another_connection(self.owner)
				if action == "disable":
					doc = frappe.get_doc("WebAuthn Credential", cred.name)
					doc.enabled = 0
					doc.save(ignore_permissions=True)
				else:
					frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
				frappe.db.commit()  # count the table as it is now, not through this request's snapshot
				self.assertEqual(self._sessions(self.owner), 0)

	def _session_ids(self, user: str) -> list[str]:
		return frappe.db.sql_list("select sid from tabSessions where user=%s", user)

	def _current_session_id(self) -> str:
		"""The current session's id as the Sessions table stores it (hashed from v16)."""
		return getattr(frappe.sessions, "hash_sid", lambda sid: sid)(frappe.session.sid)

	def test_the_owner_revoking_their_own_passkey_ends_their_other_sessions(self):
		"""A lost device's session ends when its owner revokes that passkey from another device;
		the session they are using stays, so the email doesn't say they were signed out."""
		for action in ("disable", "delete"):
			with self.subTest(action=action):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)  # the lost device
				self._sign_in_for_real(self.owner)  # the device in hand
				current = self._current_session_id()
				if action == "disable":
					doc = frappe.get_doc("WebAuthn Credential", cred.name)
					doc.enabled = 0
					doc.save(ignore_permissions=True)
				else:
					frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
				self.assertEqual(self._session_ids(self.owner), [current])
				self.assertEqual(frappe.session.user, self.owner)
		self.assertEqual(
			[mail["message"] for mail in self.sent],
			[
				"The passkey “Test Passkey” on your account was disabled by an administrator on"
				" erp.example.com. You can no longer sign in with it. Contact your administrator if this"
				" was unexpected.",
				"The passkey “Test Passkey” was removed from your account on erp.example.com and no longer"
				" works there. If your phone, computer or password manager still lists it, delete it there"
				" too. If you didn't expect this, contact your administrator.",
			],
		)

	def test_the_owner_removing_their_own_passkey_on_the_passkeys_page_ends_their_other_sessions(self):
		make_credential(self.owner)
		cred = make_credential(self.owner)
		self._sign_in_for_real(self.owner)  # the lost device
		lost = frappe.session.sid
		self._sign_in_for_real(self.owner)  # the device in hand
		current = self._current_session_id()
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": self.owner, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		with patch.object(frappe.local, "message_log", []):
			self.assertEqual(credentials.delete_credential(cred.name), {"deleted": cred.name})
			self._assert_nothing_reported(frappe.local.message_log)
		self.assertEqual(self._session_ids(self.owner), [current])
		self.assertEqual(frappe.session.user, self.owner)
		self.assertTrue(self._is_ended(lost))
		self.assertFalse(self._is_ended(frappe.session.sid))
		self.assertNotIn("You may need to sign in again", self.sent[0]["message"])

	def test_a_revocation_with_no_session_to_keep_ends_every_session_of_the_owner(self):
		"""From the console or a background job, the owner's or a System Manager's: no request
		session to keep, so every session of the owner ends, and nothing fails."""
		# None: the session id frappe.set_user leaves, the user's name; a System Manager's isn't read
		callers = (("owner", None), ("owner", ""), ("owner", "Guest"), ("Administrator", None))
		for action, (acting, sid) in itertools.product(("disable", "delete"), callers):
			with self.subTest(action=action, acting=acting, sid=sid):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)
				first = frappe.session.sid
				self._sign_in_for_real(self.owner)
				second = frappe.session.sid
				frappe.set_user(self.owner if acting == "owner" else acting)
				if sid is not None:
					frappe.session.sid = sid
				self.sent.clear()
				with patch.object(frappe.local, "message_log", []):
					self._revoke(action, cred)
					self._assert_nothing_reported(frappe.local.message_log)
				self.assertEqual(self._sessions(self.owner), 0)
				self.assertTrue(self._is_ended(first) and self._is_ended(second))

	def _next_request(self, sid: str) -> None:
		"""Resume ``sid`` from its cookie as the next request does; the current session becomes it."""
		set_request(
			method="GET", path="/api/method/frappe.auth.get_logged_user", headers={"Cookie": f"sid={sid}"}
		)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.form_dict = frappe._dict()
		frappe.local.response = frappe._dict()
		frappe.local.login_manager = LoginManager()

	def _is_cached(self, sid: str) -> bool:
		return bool(frappe.cache.hget("session", get_stored_session_id(sid)))

	def _is_ended(self, sid: str) -> bool:
		return state.is_session_ended(state.sid_hash(get_stored_session_id(sid)))

	def _revoke(self, action: str, cred) -> None:
		if action == "disable":
			doc = frappe.get_doc("WebAuthn Credential", cred.name)
			doc.enabled = 0
			doc.save(ignore_permissions=True)
		else:
			frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)

	def test_a_revocation_marks_every_session_it_ends(self):
		self.assertIn("passkeys.session.refuse_ended_session", frappe.get_hooks("before_request"))
		self.assertIn("passkeys.session.drop_ended_session", frappe.get_hooks("after_request"))
		for action in ("disable", "delete"):
			with self.subTest(action=action):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)
				first = frappe.session.sid
				self._sign_in_for_real(self.owner)
				second = frappe.session.sid
				self._sign_in_for_real(self.actor)
				self._revoke(action, cred)
				self.assertEqual(self._sessions(self.owner), 0)
				for sid in (first, second):
					self.assertFalse(self._is_cached(sid))
					self.assertTrue(self._is_ended(sid))
				self.assertFalse(self._is_ended(frappe.session.sid))

	def test_a_session_marked_ended_is_refused_and_stays_marked(self):
		"""Its next request answers 401 SessionExpired, signs the browser out and deletes the
		session; the mark outlives the refusal."""
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		state.mark_sessions_ended([state.sid_hash(get_stored_session_id(sid))], 60)
		self._next_request(sid)
		self.assertEqual(frappe.session.user, self.owner)

		with self.assertRaises(frappe.SessionExpired):
			refuse_ended_session()
		self.assertEqual(frappe.session.user, "Guest")
		self.assertEqual(frappe.local.response.session_expired, 1)
		self.assertIn("sid", frappe.local.cookie_manager.to_delete)
		self.assertEqual(self._sessions(self.owner), 0)
		self.assertFalse(self._is_cached(sid))
		self.assertTrue(self._is_ended(sid))
		self._next_request(sid)
		self.assertEqual(frappe.session.user, "Guest")

	# Ids not in the form core issues (56 lowercase hex digits), each of a different kind.
	MALFORMED_IDS = (
		"g" * 56,
		"٣" * 56,
		frappe.generate_hash(length=40),
		frappe.generate_hash() + "0",
		"A" * 56,
		frappe.generate_hash() + "\n",
	)

	@staticmethod
	def _stored_as(stored_as_is: bool):
		"""Session ids stored as they are, or (as from version-16 on) as a hash."""
		return (lambda sid: sid) if stored_as_is else (lambda sid: hashlib.sha256(sid.encode()).hexdigest())

	def test_a_signed_in_id_not_in_the_form_core_issues_is_refused(self):
		"""Where core stores session ids as they are: 401 SessionExpired, the browser signed out and
		that id's cached copy dropped, without a mark read and without ending a session. Where core
		stores a hash of the id, the ended-session check decides."""
		self._sign_in_for_real(self.owner)
		signed_in = frappe.session.sid
		for stored_as_is in (True, False):
			for sid in self.MALFORMED_IDS:
				with self.subTest(stored_as_is=stored_as_is, sid=sid):
					self._next_request(signed_in)
					frappe.session.sid = sid
					with (
						patch.object(
							session, "get_stored_session_id", side_effect=self._stored_as(stored_as_is)
						),
						patch("frappe.sessions.delete_session") as delete_session,
						patch.object(frappe.cache, "hdel", wraps=frappe.cache.hdel) as hdel,
						patch.object(state, "is_session_ended", wraps=state.is_session_ended) as is_ended,
					):
						if stored_as_is:
							with self.assertRaises(frappe.SessionExpired):
								refuse_ended_session()
						else:
							refuse_ended_session()
					delete_session.assert_not_called()
					self.assertEqual(self._sessions(self.owner), 1)
					if stored_as_is:
						self.assertEqual(frappe.session.user, "Guest")
						self.assertEqual(frappe.local.response.session_expired, 1)
						self.assertIn("sid", frappe.local.cookie_manager.to_delete)
						self.assertEqual(
							hdel.call_args_list, [call("session", sid), call("last_db_session_update", sid)]
						)
						is_ended.assert_not_called()
					else:
						self.assertEqual(frappe.session.user, self.owner)
						hdel.assert_not_called()
						is_ended.assert_called_once()

	def test_after_its_request_an_id_not_in_the_form_core_issues_is_dropped_without_a_mark_read(self):
		self._sign_in_for_real(self.owner)
		signed_in = frappe.session.sid
		for stored_as_is in (True, False):
			for sid in self.MALFORMED_IDS:
				with self.subTest(stored_as_is=stored_as_is, sid=sid):
					self._next_request(signed_in)
					frappe.local.session_obj.sid = sid
					frappe.local.request.after_response = CallbackManager()
					stored_as = self._stored_as(stored_as_is)
					with (
						patch.object(session, "get_stored_session_id", side_effect=stored_as),
						patch.object(frappe.cache, "hdel", wraps=frappe.cache.hdel) as hdel,
						patch.object(state, "is_session_ended", wraps=state.is_session_ended) as is_ended,
					):
						drop_ended_session()
						frappe.local.request.after_response.run()
					if stored_as_is:
						self.assertEqual(
							hdel.call_args_list, [call("session", sid), call("last_db_session_update", sid)]
						)
						is_ended.assert_not_called()
					else:
						hdel.assert_not_called()
						is_ended.assert_called_once_with(state.sid_hash(stored_as(sid)))
		self.assertTrue(self._is_cached(signed_in))

	def _bearer_token(self, user: str) -> str:
		client = frappe.get_doc(
			doctype="OAuth Client",
			app_name=f"passkeys-test-{frappe.generate_hash(length=8)}",
			scopes="all",
			redirect_uris="http://localhost",
			default_redirect_uri="http://localhost",
			grant_type="Authorization Code",
			response_type="Code",
		).insert(ignore_permissions=True)
		self.addCleanup(self._delete_committed, "OAuth Client", client.name)
		token = frappe.get_doc(
			doctype="OAuth Bearer Token",
			access_token=frappe.generate_hash(),
			client=client.name,
			expires_in=3600,
			scopes="all",
			status="Active",
			user=user,
		).insert(ignore_permissions=True)
		self.addCleanup(self._delete_committed, "OAuth Bearer Token", token.name)
		return token.access_token

	@staticmethod
	def _delete_committed(doctype: str, name: str):
		# The requests below commit these rows (core ends the unknown cookie's session), and the class
		# cleanup starts with a rollback: delete and commit here.
		frappe.delete_doc(doctype, name, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	def test_token_and_bearer_requests_are_never_refused(self):
		"""Not even with a session cookie that names no session: core resumes such a cookie as Guest
		before these checks and signs the request in from its Authorization header after."""
		api_key, api_secret = frappe.generate_hash(length=15), frappe.generate_hash(length=15)
		frappe.db.set_value("User", self.owner, "api_key", api_key)
		set_encrypted_password("User", self.owner, api_secret, "api_secret")
		authorizations = {
			"token": f"token {api_key}:{api_secret}",
			"basic": "Basic " + base64.b64encode(f"{api_key}:{api_secret}".encode()).decode(),
			"bearer": f"Bearer {self._bearer_token(self.owner)}",
		}
		for kind, authorization in authorizations.items():
			for cookie in (None, "Guest", "not-a-session-id", "g" * 56, frappe.generate_hash()):
				with self.subTest(kind=kind, cookie=cookie):
					headers = {"Authorization": authorization}
					if cookie:
						headers["Cookie"] = f"sid={cookie}"
					set_request(method="GET", path="/api/method/frappe.auth.get_logged_user", headers=headers)
					frappe.local.cookie_manager = CookieManager()
					frappe.local.form_dict = frappe._dict()
					frappe.local.response = frappe._dict()
					frappe.local.login_manager = LoginManager()
					frappe.local.request.after_response = CallbackManager()
					refuse_ended_session()  # before_request
					frappe.auth.validate_auth()
					self.assertEqual(frappe.session.user, self.owner)
					refuse_ended_session()
					drop_ended_session()
					self.assertEqual(len(frappe.local.request.after_response._functions), 0)

	def test_a_marked_session_is_dropped_after_its_request(self):
		self._sign_in_for_real(self.owner)
		marked = frappe.session.sid
		self._sign_in_for_real(self.owner)
		unmarked = frappe.session.sid
		state.mark_sessions_ended([state.sid_hash(get_stored_session_id(marked))], 60)
		for sid in (marked, unmarked):
			self._next_request(sid)
			frappe.local.request.after_response = CallbackManager()
			drop_ended_session()
			self.assertEqual(len(frappe.local.request.after_response._functions), 1)
			frappe.local.request.after_response.run()
		self.assertFalse(self._is_cached(marked))
		self.assertTrue(self._is_cached(unmarked))

	def test_the_session_an_owner_revokes_from_keeps_working(self):
		cred = make_credential(self.owner)
		self._sign_in_for_real(self.owner)  # the lost device
		lost = frappe.session.sid
		self._sign_in_for_real(self.owner)  # the device in hand
		current = frappe.session.sid
		frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
		self._next_request(current)
		refuse_ended_session()
		self.assertEqual(frappe.session.user, self.owner)
		self.assertTrue(self._is_cached(current))
		self.assertFalse(self._is_ended(current))
		self.assertTrue(self._is_ended(lost))

	def test_ending_sessions_ends_every_cached_session_of_the_user(self):
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		self._sign_in_for_real(self.actor)
		with patch.object(session, "_get_session_keys", return_value=set()):
			end_sessions(self.owner, keep_current=False)
		self.assertFalse(self._is_cached(sid))
		self.assertTrue(self._is_ended(sid))
		self.assertTrue(self._is_cached(frappe.session.sid))

	def test_ending_sessions_lists_every_session_at_once(self):
		sessions = frappe.qb.DocType("Sessions")
		insert = frappe.qb.into(sessions).columns(
			sessions.sid, sessions.user, sessions.sessiondata, sessions.lastupdate, sessions.status
		)
		keys = [frappe.generate_hash() for _ in range(105)]
		for key in keys:
			insert = insert.insert((key, self.owner, "{}", frappe.utils.now(), "Active"))
		insert.run()
		with (
			patch("frappe.core.doctype.activity_log.feed.logout_feed"),
			patch.object(session, "_get_cached_sessions", wraps=session._get_cached_sessions) as read,
			patch.object(session, "_get_session_keys", wraps=session._get_session_keys) as listing,
		):
			self.assertTrue(end_sessions(self.owner, keep_current=False))
		self.assertEqual(self._sessions(self.owner), 0)
		self.assertTrue(all(state.is_session_ended(state.sid_hash(key)) for key in keys))
		# one listing ends all 105, the next finds none; the cache is read once
		self.assertEqual((listing.call_count, read.call_count), (2, 1))

	def test_a_marking_failure_still_ends_the_sessions(self):
		self._sign_in_for_real(self.owner)
		self._sign_in_for_real(self.actor)
		with patch.object(state, "mark_sessions_ended", side_effect=RuntimeError("cache write failed")):
			self.assertFalse(end_sessions(self.owner, keep_current=False))
		self.assertEqual(self._sessions(self.owner), 0)

	def test_a_revocation_the_cache_cannot_mark_still_completes_and_is_reported(self):
		"""Tried three times; the sessions end, the owner is emailed, the save or delete runs to the
		end, a risk event is recorded, the System Managers are emailed, and the acting user is told
		to clear the site cache, or to ask an administrator to when they can't."""
		down = redis.exceptions.ConnectionError("cache down")
		records = {
			"disable": lambda cred: ("Version", {"ref_doctype": cred.doctype, "docname": cred.name}),
			"delete": lambda cred: (
				"Deleted Document",
				{"deleted_doctype": cred.doctype, "deleted_name": cred.name},
			),
		}
		instructions = {
			"actor": "Ask an administrator to clear the site cache",
			"Administrator": "Clear the site cache once it can be reached",
		}
		risk = {"user": self.owner, "content": f"passkeys:{notifications.RISK_SIGN_OUT_INCOMPLETE}"}
		for (action, record), (acting, instruction) in (
			(pair, other) for pair in records.items() for other in instructions.items()
		):
			with self.subTest(action=action, acting=acting):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)
				if acting == "actor":
					self._sign_in_for_real(self.actor)
				else:
					frappe.set_user("Administrator")
				sent, risk_events = len(self.sent), activity_log_count(risk)
				with (
					patch.object(state, "mark_sessions_ended", side_effect=down) as mark,
					patch.object(session.time, "sleep") as sleep,
					patch.object(frappe.local, "message_log", []),
					patch("frappe.utils.user.get_system_managers", return_value=["manager@example.com"]),
				):
					if action == "disable":  # tests skip version history unless asked
						doc = frappe.get_doc("WebAuthn Credential", cred.name)
						doc.enabled = 0
						doc.save(ignore_permissions=True, ignore_version=False)
					else:
						self._revoke(action, cred)
					warnings = [message.message for message in frappe.local.message_log]
				self.assertEqual(mark.call_count, 3)
				self.assertEqual([call.args for call in sleep.call_args_list], [(0.1,), (0.3,)])
				self.assertEqual(self._sessions(self.owner), 0)
				self.assertTrue(frappe.db.exists(*record(cred)))
				self.assertEqual(activity_log_count(risk), risk_events + 1)
				mails = self.sent[sent:]
				self.assertEqual(
					[mail["recipients"] for mail in mails], [[self.owner], ["manager@example.com"]]
				)
				self.assertIn(f"some of {self.owner}'s sessions may still be signed in", mails[1]["message"])
				self.assertIn("recovery.html#someone-may-be-using-the-account-right-now", mails[1]["message"])
				self.assertEqual(len(warnings), 1)
				self.assertIn(f"some of {self.owner}'s sessions may still be signed in", warnings[0])
				self.assertIn(instruction, warnings[0])
				self.assertIn("recovery.html#someone-may-be-using-the-account-right-now", warnings[0])

	def test_the_delete_endpoint_returns_an_incomplete_sign_out_warning_to_the_owner(self):
		"""The response the passkey dialogs read carries the warning as an orange message."""
		make_credential(self.owner)
		cred = make_credential(self.owner)
		self._sign_in_for_real(self.owner)  # the lost device
		self._sign_in_for_real(self.owner)  # the device in hand
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": self.owner, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		self.addCleanup(setattr, frappe.local, "response", frappe.local.response)
		frappe.local.response = frappe._dict()
		with (
			patch.object(
				state, "mark_sessions_ended", side_effect=redis.exceptions.ConnectionError("cache down")
			),
			patch.object(session.time, "sleep"),
			patch.object(frappe.local, "message_log", []),
			patch("frappe.utils.user.get_system_managers", return_value=["manager@example.com"]),
		):
			self.assertEqual(credentials.delete_credential(cred.name), {"deleted": cred.name})
			make_logs()
		messages = [json.loads(message) for message in json.loads(frappe.local.response["_server_messages"])]
		self.assertEqual([message["indicator"] for message in messages], ["orange"])
		self.assertIn(f"some of {self.owner}'s sessions may still be signed in", messages[0]["message"])
		self.assertIn("Ask an administrator to clear the site cache", messages[0]["message"])

	def _log_traceback_variables(self) -> None:
		"""Developer mode, where Frappe logs a traceback's variables by default."""
		self.addCleanup(setattr, frappe.conf, "developer_mode", frappe.conf.get("developer_mode"))
		frappe.conf.developer_mode = 1

	def _revoke_and_collect(self, action: str, cred) -> frappe._dict:
		"""Revoke as the Desk form does, version history on: what it showed, mailed, logged and
		recorded."""
		risk = {"user": self.owner, "content": f"passkeys:{notifications.RISK_SIGN_OUT_INCOMPLETE}"}
		operation = {"disable": "passkey_disabled", "delete": "passkey_removed"}[action]
		audit = {"user": self.owner, "content": f"passkeys:{operation}"}
		before = set(frappe.get_all("Error Log", pluck="name"))
		sent, risk_events, audit_rows = len(self.sent), activity_log_count(risk), activity_log_count(audit)
		with (
			patch.object(frappe.local, "message_log", []),
			patch("frappe.utils.user.get_system_managers", return_value=["manager@example.com"]),
		):
			if action == "disable":  # tests skip version history unless asked
				doc = frappe.get_doc("WebAuthn Credential", cred.name)
				doc.enabled = 0
				doc.save(ignore_permissions=True, ignore_version=False)
			else:
				frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
			warnings = [message.message for message in frappe.local.message_log]
		logs = frappe.get_all(
			"Error Log",
			filters={"name": ["not in", list(before) or [""]]},
			fields=["name", "method", "error"],
		)
		for log in logs:
			self.addCleanup(frappe.delete_doc, "Error Log", log.name, force=1, ignore_permissions=True)
		return frappe._dict(
			warnings=warnings,
			mails=self.sent[sent:],
			logs=logs,
			risk_events=activity_log_count(risk) - risk_events,
			audit_rows=activity_log_count(audit) - audit_rows,
		)

	def _assert_completed_and_reported(self, action: str, cred, result, sids: tuple) -> None:
		"""The save or delete ran to its end, the owner's email and audit row went, and the sign-out
		was reported incomplete; the logs hold no session id."""
		record = {
			"disable": ("Version", {"ref_doctype": cred.doctype, "docname": cred.name}),
			"delete": ("Deleted Document", {"deleted_doctype": cred.doctype, "deleted_name": cred.name}),
		}[action]
		self.assertTrue(frappe.db.exists(*record))
		self.assertEqual((result.audit_rows, result.risk_events), (1, 1))
		self.assertEqual(
			[mail["recipients"] for mail in result.mails], [[self.owner], ["manager@example.com"]]
		)
		self.assertEqual(len(result.warnings), 1)
		self.assertIn(f"some of {self.owner}'s sessions may still be signed in", result.warnings[0])
		self.assertIn("Ask an administrator to clear the site cache", result.warnings[0])
		text = "\n".join(log.error for log in result.logs)
		for sid in sids:
			stored_id = get_stored_session_id(sid)
			for form in (sid, stored_id, state.sid_hash(stored_id)):
				self.assertNotIn(form, text)

	def test_a_session_that_fails_to_end_leaves_the_others_ended_and_is_reported(self):
		self._log_traceback_variables()
		real_delete = frappe.sessions.delete_session
		for action in ("disable", "delete"):
			with self.subTest(action=action):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)
				failing = frappe.session.sid
				self._sign_in_for_real(self.owner)
				ended = frappe.session.sid
				self._sign_in_for_real(self.actor)
				failing_id = get_stored_session_id(failing)

				@functools.wraps(real_delete)
				def delete_session(sid=None, user=None, reason="Session Expired", **kwargs):
					if failing_id in (sid, kwargs.get("sid_hash")):
						raise RuntimeError("database write failed")
					return real_delete(sid, user, reason, **kwargs)

				with patch("frappe.sessions.delete_session", delete_session):
					result = self._revoke_and_collect(action, cred)
				remaining = set(self._session_ids(self.owner))
				self.assertEqual(remaining & {failing_id, get_stored_session_id(ended)}, {failing_id})
				self.assertTrue(self._is_ended(failing) and self._is_ended(ended))
				self.assertEqual({log.method for log in result.logs}, {"passkeys: ending a session failed"})
				self._assert_completed_and_reported(action, cred, result, (failing, ended))

	def test_a_sign_out_that_fails_part_way_is_reported_and_the_revocation_completes(self):
		"""Here the second listing, for sessions signed in meanwhile, fails after the first ended
		the lost device's session."""
		self._log_traceback_variables()
		real_listing = session._get_session_keys
		for action in ("disable", "delete"):
			with self.subTest(action=action):
				cred = make_credential(self.owner)
				self._sign_in_for_real(self.owner)  # the lost device
				lost = frappe.session.sid
				self._sign_in_for_real(self.owner)  # the device in hand
				listings = []

				def list_once(*args):
					listings.append(args)
					if len(listings) > 1:
						raise RuntimeError("database read failed")
					return real_listing(*args)

				with patch.object(session, "_get_session_keys", list_once):
					result = self._revoke_and_collect(action, cred)
				self.assertEqual(self._session_ids(self.owner), [self._current_session_id()])
				self.assertTrue(self._is_ended(lost))
				self.assertEqual({log.method for log in result.logs}, {"passkeys: sign-out failed"})
				self._assert_completed_and_reported(action, cred, result, (lost, frappe.session.sid))

	def _fail_session_expiry_reads(self):
		"""Make the Sessions expiry read fail as a database error would, its query in the frame.
		Patched on the connection object itself, so an earlier test's wrapper can't shadow it."""
		db = frappe.local.db
		sql = db.sql

		def failing_sql(query, *args, **kwargs):
			text = str(query).lstrip().lower()
			if text.startswith("select") and "sessiondata" in text:
				raise RuntimeError("database read failed")
			return sql(query, *args, **kwargs)

		return patch.object(db, "sql", failing_sql)

	def test_an_expiry_read_failure_marks_past_the_site_setting(self):
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		self._sign_in_for_real(self.actor)
		with (
			self._fail_session_expiry_reads(),
			patch("frappe.sessions.get_expiry_period", return_value="00:01:00"),
		):
			self.assertTrue(end_sessions(self.owner, keep_current=False))
		self.assertEqual(self._sessions(self.owner), 0)
		marks = {frappe.safe_decode(field): int(until) for field, until in self._ended_marks().items()}
		expected = time.time() + 60 + state.ENDED_SESSION_MARGIN
		self.assertTrue(expected - 60 <= marks[state.sid_hash(get_stored_session_id(sid))] <= expected)

	def test_a_logged_sign_out_failure_holds_no_session_id(self):
		"""Even with developer mode on, where Frappe logs a traceback's variables by default."""
		self.addCleanup(setattr, frappe.conf, "developer_mode", frappe.conf.get("developer_mode"))
		frappe.conf.developer_mode = 1
		self._sign_in_for_real(self.owner)
		listed = frappe.session.sid
		self._sign_in_for_real(self.owner)
		kept = frappe.session.sid
		before = set(frappe.get_all("Error Log", pluck="name"))
		with (
			patch.object(redis.Redis, "hscan_iter", side_effect=RuntimeError("cache read failed")),
			patch.object(state, "mark_sessions_ended", side_effect=RuntimeError("cache write failed")),
			self._fail_session_expiry_reads(),
		):
			self.assertFalse(end_sessions(self.owner, keep_current=True))
		logs = frappe.get_all(
			"Error Log",
			filters={"name": ["not in", list(before) or [""]]},
			fields=["name", "method", "error"],
		)
		for log in logs:
			self.addCleanup(frappe.delete_doc, "Error Log", log.name, force=1, ignore_permissions=True)
		self.assertEqual(
			{log.method for log in logs},
			{
				"passkeys: cached-session read failed",
				"passkeys: ended-session mark failed",
				"passkeys: session expiry read failed",
			},
		)
		text = "\n".join(log.error for log in logs)
		for sid in (listed, kept):
			stored_id = get_stored_session_id(sid)
			for form in (sid, stored_id, state.sid_hash(stored_id)):
				self.assertNotIn(form, text)

	def test_listed_sessions_are_marked_when_the_cache_read_fails(self):
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		self._sign_in_for_real(self.actor)
		with patch.object(session, "_get_cached_sessions", side_effect=RuntimeError("bad value")):
			self.assertFalse(end_sessions(self.owner, keep_current=False))
		self.assertTrue(self._is_ended(sid))
		self.assertEqual(self._sessions(self.owner), 0)

	def test_the_cache_read_matches_the_user_a_session_resumes_as_and_skips_unreadable_values(self):
		"""Version-15 caches the session data under ``data``; version-16 caches the data itself."""
		owner_v15, actor_v15, owner_v16 = (frappe.generate_hash() for _ in range(3))
		values = [
			(b"unreadable", b"not a pickle"),
			(owner_v15.encode(), pickle.dumps({"user": self.actor, "data": {"user": self.owner}})),
			(actor_v15.encode(), pickle.dumps({"user": self.owner, "data": {"user": self.actor}})),
			(owner_v16.encode(), pickle.dumps({"user": self.owner, "session_expiry": "06:00:00"})),
		]
		with patch.object(redis.Redis, "hscan_iter", return_value=iter(values)):
			self.assertTrue(end_sessions(self.owner, keep_current=False))
		ended = [state.is_session_ended(state.sid_hash(key)) for key in (owner_v15, actor_v15, owner_v16)]
		self.assertEqual(ended, [True, False, True])

	def test_the_mark_reads_each_session_s_own_expiry_field(self):
		"""A user-controlled field that reads like an expiry doesn't shorten the mark, in either
		stored form."""
		crafted = "x 'session_expiry':'00:00:01'"
		stored = {
			frappe.generate_hash(): json.dumps(
				{"full_name": crafted, "session_expiry": "240:00:00"}, sort_keys=True, separators=(",", ":")
			),
			frappe.generate_hash(): str({"session_ip": crafted, "session_expiry": "240:00:00"}),
		}
		sessions = frappe.qb.DocType("Sessions")
		insert = frappe.qb.into(sessions).columns(
			sessions.sid, sessions.user, sessions.sessiondata, sessions.lastupdate, sessions.status
		)
		for key, sessiondata in stored.items():
			insert = insert.insert((key, self.owner, sessiondata, frappe.utils.now(), "Active"))
		insert.run()
		with (
			patch("frappe.core.doctype.activity_log.feed.logout_feed"),
			patch("frappe.sessions.get_expiry_period", return_value="06:00:00"),
		):
			self.assertTrue(end_sessions(self.owner, keep_current=False))
		marks = {frappe.safe_decode(field): int(until) for field, until in self._ended_marks().items()}
		expected = time.time() + 240 * 3600 + state.ENDED_SESSION_MARGIN
		for key in stored:
			self.assertTrue(expected - 60 <= marks[state.sid_hash(key)] <= expected)

	def test_ending_sessions_ends_exactly_what_it_marks(self):
		"""A session listed after a round's listing is marked in the next round before it ends."""
		sessions = frappe.qb.DocType("Sessions")

		def add_owner_session():
			key = frappe.generate_hash()
			frappe.qb.into(sessions).columns(
				sessions.sid, sessions.user, sessions.sessiondata, sessions.lastupdate, sessions.status
			).insert((key, self.owner, "{}", frappe.utils.now(), "Active")).run()
			return key

		keys = [add_owner_session()]
		listing = session._get_session_keys

		def list_then_sign_in(*args, **kwargs):
			listed = listing(*args, **kwargs)
			if len(keys) == 1:
				keys.append(add_owner_session())
			return listed

		with (
			patch("frappe.core.doctype.activity_log.feed.logout_feed"),
			patch.object(session, "_get_session_keys", side_effect=list_then_sign_in),
		):
			self.assertTrue(end_sessions(self.owner, keep_current=False))
		self.assertEqual(self._sessions(self.owner), 0)
		self.assertEqual([state.is_session_ended(state.sid_hash(key)) for key in keys], [True, True])

	def test_ending_sessions_stops_when_a_round_ends_none(self):
		"""It stops, and reports the sign-out incomplete: the sessions are still there."""
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		self._sign_in_for_real(self.actor)
		ended = []

		def end_at_most_five(*args, **kwargs):
			ended.append(kwargs)
			if len(ended) > 5:
				raise AssertionError("still ending sessions")

		with (
			patch("frappe.sessions.delete_session", side_effect=end_at_most_five),
			patch.object(session, "_get_session_keys", wraps=session._get_session_keys) as listing,
		):
			self.assertFalse(end_sessions(self.owner, keep_current=False))
		self.assertEqual(listing.call_count, 2)
		self.assertTrue(self._is_ended(sid))

	def test_ending_sessions_stops_at_its_round_limit(self):
		"""Incomplete (logged) when sessions are still left at the limit; complete when none is."""
		for is_any_left in (True, False):
			with self.subTest(is_any_left=is_any_left):
				listings = []

				def a_new_session_each_round(*args):
					listings.append(args)
					if len(listings) > session.MAX_SIGN_OUT_ROUNDS + 5:
						raise AssertionError("still listing sessions")
					if len(listings) > session.MAX_SIGN_OUT_ROUNDS and not is_any_left:
						return set()
					return {frappe.generate_hash()}

				with (
					patch("frappe.sessions.delete_session"),
					patch.object(session, "_get_session_keys", side_effect=a_new_session_each_round),
					patch("frappe.log_error") as log_error,
				):
					self.assertEqual(end_sessions(self.owner, keep_current=False), not is_any_left)
				self.assertEqual(len(listings), session.MAX_SIGN_OUT_ROUNDS + 1)
				if is_any_left:
					log_error.assert_called_once_with(title="passkeys: sign-out stopped at its round limit")
				else:
					log_error.assert_not_called()

	def test_an_unreachable_cache_counts_as_not_ended(self):
		"""Logged once per worker; the request goes on as the signed-in user."""
		self._sign_in_for_real(self.owner)
		self._next_request(frappe.session.sid)
		down = redis.exceptions.ConnectionError("cache down")
		with (
			patch.object(state, "_is_cache_error_logged", False),
			patch("frappe.logger") as logger,
			patch.object(frappe.cache, "execute_command", side_effect=down),
		):
			refuse_ended_session()
			drop_session_if_ended(get_stored_session_id(frappe.session.sid))
		self.assertEqual(frappe.session.user, self.owner)
		self.assertEqual(logger.return_value.warning.call_count, 1)

	def test_the_queued_check_holds_no_session_id_and_never_raises(self):
		self._sign_in_for_real(self.owner)
		sid = frappe.session.sid
		self._next_request(sid)
		frappe.local.request.after_response = CallbackManager()
		drop_ended_session()
		(check,) = frappe.local.request.after_response._functions
		for session_id in (sid, get_stored_session_id(sid)):
			self.assertNotIn(session_id, repr(check))
		with (
			patch.object(state, "is_session_ended", side_effect=redis.exceptions.TimeoutError("slow")),
			patch("frappe.logger") as logger,
		):
			check()
		logger.return_value.error.assert_called_once_with("ended-session check failed: TimeoutError")

	def test_the_mark_outlasts_each_ended_session_and_holds_no_session_id(self):
		"""Kept past the longer of the site's session expiry and the session's own, plus a day."""
		cred = make_credential(self.owner)
		self._sign_in_for_real(self.owner)
		sid, stored_id = frappe.session.sid, get_stored_session_id(frappe.session.sid)
		own_expiry = frappe.sessions.get_expiry_in_seconds()
		self._sign_in_for_real(self.actor)
		with patch("frappe.sessions.get_expiry_period", return_value="00:01:00"):  # shortened since
			frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
		marks = {frappe.safe_decode(field): int(until) for field, until in self._ended_marks().items()}
		until = marks[state.sid_hash(stored_id)]
		expected = time.time() + own_expiry + state.ENDED_SESSION_MARGIN
		self.assertTrue(expected - 60 <= until <= expected)
		self.assertFalse({sid, stored_id} & set(marks))

	def test_a_signed_in_request_costs_two_cache_reads_and_guest_none(self):
		self._next_request("Guest")
		frappe.local.request.after_response = CallbackManager()
		with patch.object(frappe.cache, "execute_command", wraps=frappe.cache.execute_command) as cache:
			refuse_ended_session()
			drop_ended_session()
			frappe.local.request.after_response.run()
		cache.assert_not_called()
		self._sign_in_for_real(self.owner)
		self._next_request(frappe.session.sid)
		frappe.local.request.after_response = CallbackManager()
		with patch.object(frappe.cache, "execute_command", wraps=frappe.cache.execute_command) as cache:
			refuse_ended_session()
			drop_ended_session()
			frappe.local.request.after_response.run()
		self.assertEqual(cache.call_count, 2)
		self.assertEqual(frappe.session.user, self.owner)


class ReauthUnderDisableUserPassTest(_Base):
	"""With site ``disable_user_pass_login`` on, a password can
	no longer re-auth for management once the user holds ≥1 passkey."""

	def setUp(self):
		super().setUp()
		self._orig = frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		self._set_disable(1)
		self.addCleanup(self._restore)

	def _restore(self):
		self._set_disable(self._orig or 0)

	def _set_disable(self, value):
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", value)
		bust_system_settings_cache()

	def test_reauth_password_refused_for_a_passkey_holder(self):
		user = self._user()
		make_credential(user)
		sign_in(user)
		with self.assertRaises(frappe.AuthenticationError):
			confirm.reauth_password(PWD)
