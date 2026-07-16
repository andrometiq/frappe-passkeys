# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Phase-6 management server behaviors on the live bench: out-of-band
notifications, risk-event telemetry, the admin
lockout interlock, and the row-7 reauth refusal under
``disable_user_pass_login``."""

import types

import frappe

from passkeys import confirm, notifications, passkey, state
from passkeys.api import credentials
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user

PWD = "Secret_passw0rd_9x!"


class _Base(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(
			lambda u=user: frappe.db.exists("User", u)
			and frappe.delete_doc("User", u, force=1, ignore_permissions=True)
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
		frappe.set_user("Administrator")
		for field in ("passkey_notify_on_change", "passkey_notify_password_fallback"):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		flush_settings_cache()

	def _subjects(self):
		return " ".join(m["subject"].lower() for m in self.sent)

	def test_added_email_sent_when_knob_on(self):
		user = self._user()
		notifications.notify_credential_added(user, "Phone", ip="203.0.113.7")
		self.assertEqual(len(self.sent), 1)
		self.assertIn(user, self.sent[0]["recipients"])
		self.assertIn("added", self.sent[0]["subject"].lower())

	def test_no_email_when_notify_knob_off_but_activity_still_logged(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_on_change", 0)
		flush_settings_cache()
		before = frappe.db.count("Activity Log", {"user": user})
		notifications.notify_credential_added(user, "Phone")
		self.assertEqual(self.sent, [])
		self.assertEqual(frappe.db.count("Activity Log", {"user": user}), before + 1)

	def test_removed_email_on_endpoint_delete(self):
		user = self._user()
		make_credential(user)
		drop = make_credential(user)
		frappe.set_user(user)
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		self.sent.clear()
		credentials.delete_credential(drop.name)
		self.assertIn("removed", self._subjects())

	def test_flagged_email_sent_once_on_sign_count_regression(self):
		user = self._user()
		cred = make_credential(user, sign_count=10, flagged=0)
		result = types.SimpleNamespace(
			new_sign_count=5,
			sign_count_to_store=10,
			backup_state=False,
			sign_count_regression=True,
		)
		passkey._advance_credential(cred.name, result)
		flagged_mails = [m for m in self.sent if "flag" in m["subject"].lower()]
		self.assertEqual(len(flagged_mails), 1)
		# a second regressed assertion must NOT re-spam (already flagged)
		passkey._advance_credential(cred.name, result)
		self.assertEqual(len([m for m in self.sent if "flag" in m["subject"].lower()]), 1)

	def test_fallback_risk_event_emails_under_its_own_knob(self):
		user = self._user()
		notifications.record_risk_event(notifications.RISK_FALLBACK_USED, user, "otp fallback")
		self.assertEqual(len(self.sent), 1)  # passkey_notify_password_fallback == 1

	def test_fallback_risk_event_silent_when_knob_off(self):
		user = self._user()
		frappe.db.set_single_value("Passkey Settings", "passkey_notify_password_fallback", 0)
		flush_settings_cache()
		before = frappe.db.count("Activity Log", {"user": user})
		notifications.record_risk_event(notifications.RISK_FALLBACK_USED, user, "otp fallback")
		self.assertEqual(self.sent, [])
		self.assertEqual(frappe.db.count("Activity Log", {"user": user}), before + 1)


class AdminInterlockTest(_Base):
	"""Lockout interlock: a System Manager cannot disable/delete the last
	enabled credential of a passkey-only user; owner notice is still sent; the
	User-delete cascade is never blocked by it."""

	def setUp(self):
		super().setUp()
		self.sent = []
		self._orig_sendmail = frappe.sendmail
		frappe.sendmail = lambda **kw: self.sent.append(kw)
		self.addCleanup(setattr, frappe, "sendmail", self._orig_sendmail)

	def test_admin_delete_last_credential_of_passkey_only_user_blocked(self):
		user = self._user()
		cred = make_credential(user)
		make_handle(user, passkey_only_login=1)
		frappe.set_user("Administrator")
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
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None  # bust the request-local singles cache

	def test_reauth_password_refused_for_a_passkey_holder(self):
		user = self._user()
		make_credential(user)
		frappe.set_user(user)
		with self.assertRaises(frappe.AuthenticationError):
			confirm.reauth_password(PWD)
