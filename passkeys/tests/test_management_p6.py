# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Phase-6 management server behaviors on the live bench: out-of-band
notifications, risk-event telemetry, the admin
lockout interlock, and the row-7 reauth refusal under
``disable_user_pass_login``."""

import types
from unittest.mock import patch

import frappe
from frappe.auth import CookieManager, LoginManager
from frappe.utils import set_request

from passkeys import ceremony, confirm, notifications, state
from passkeys.api import credentials
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

	def test_someone_elses_disable_signs_the_owner_out_everywhere(self):
		cred = make_credential(self.owner)
		self._two_owner_sessions_then_actor()
		doc = frappe.get_doc("WebAuthn Credential", cred.name)
		doc.enabled = 0
		doc.save(ignore_permissions=True)
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
		frappe.delete_doc("WebAuthn Credential", cred.name, ignore_permissions=True)
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
