# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Token-authenticated requests (API key, Basic, OAuth bearer) reach passkey
management, confirmation and sudo-window minting only through a real browser
session. Core binds a token caller with ``frappe.set_user``, which leaves
``sid == user``; these tests drive Frappe's own ``validate_auth`` to get that shape."""

import base64

import frappe
from frappe.auth import CookieManager, LoginManager, validate_auth
from frappe.utils import set_request
from frappe.utils.password import update_password

from passkeys import confirm, passkey, session, state
from passkeys.api import credentials, registration
from passkeys.errors import BrowserSessionRequired
from passkeys.tests import fake_webauthn
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_user, sign_in

PWD = "Secret_passw0rd_9x!"
REFUND_ACTION = "tests.token_auth.refund"


class TokenAuthTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")
		self.user = make_user()
		self.addCleanup(frappe.delete_doc, "User", self.user, force=1, ignore_permissions=True)
		update_password(self.user, PWD)
		self.api_key, self.api_secret = frappe.generate_hash(length=15), frappe.generate_hash(length=15)
		user_doc = frappe.get_doc("User", self.user)
		user_doc.api_key, user_doc.api_secret = self.api_key, self.api_secret
		user_doc.save(ignore_permissions=True)
		self.refund_calls = []

		@confirm.passkey_protected(action=REFUND_ACTION, bind_params=["amount"], allow_password_fallback=True)
		def refund(amount=None):
			self.refund_calls.append(amount)
			return amount

		self.refund = refund

	def _request(self, headers=None):
		set_request(method="POST", path="/api/method/passkeys.probe", headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.form_dict = frappe._dict()
		frappe.local.response = frappe._dict()

	def _authenticate_with_token(self, scheme="token"):
		"""Authenticate this request exactly as core does for ``Authorization: token|Basic``."""
		secret = f"{self.api_key}:{self.api_secret}"
		if scheme == "Basic":
			secret = base64.b64encode(secret.encode()).decode()
		frappe.set_user("Guest")
		self._request(headers=[("Authorization", f"{scheme} {secret}")])
		login_manager = LoginManager.__new__(LoginManager)
		login_manager.user = "Guest"
		frappe.local.login_manager = login_manager
		try:
			validate_auth()
		finally:
			del frappe.local.login_manager
		self.assertEqual(frappe.session.user, self.user)
		self.assertFalse(session.is_browser_session())

	def _management_calls(self):
		name = make_credential(self.user).name
		fingerprint = session.payload_hash({"amount": 50})
		return {
			"reauth_password": lambda: confirm.reauth_password(PWD),
			"reauth_password_grant": lambda: confirm.reauth_password(
				PWD, action=REFUND_ACTION, payload_fingerprint=fingerprint
			),
			"begin_confirmation": lambda: confirm.begin_confirmation(session.MANAGE_ACTION),
			"verify_confirmation": lambda: confirm.verify_confirmation("state", {"id": "x"}),
			"begin_registration": lambda: registration.begin_registration(),
			"verify_registration": lambda: registration.verify_registration("state", {"id": "x"}),
			"list_credentials": credentials.list_credentials,
			"rename_credential": lambda: credentials.rename_credential(name, "renamed"),
			"delete_credential": lambda: credentials.delete_credential(name),
			"set_passkey_only_login": lambda: credentials.set_passkey_only_login(1),
			"get_signal_data": passkey.get_signal_data,
			"record_nudge": lambda: passkey.record_nudge("shown"),
			"record_enforcement": lambda: passkey.record_enforcement("defer"),
		}

	def test_every_signed_in_endpoint_refuses_a_token_caller(self):
		for scheme in ("token", "Basic"):
			for endpoint, call in self._management_calls().items():
				with self.subTest(scheme=scheme, endpoint=endpoint):
					self._authenticate_with_token(scheme)
					with self.assertRaises(BrowserSessionRequired):
						call()
		self.assertTrue(frappe.db.exists("WebAuthn Credential", {"user": self.user}))
		self.assertIsNone(state.get_sudo_window(self.user))

	def test_password_reauth_over_a_token_mints_no_window(self):
		self._authenticate_with_token()
		with self.assertRaises(BrowserSessionRequired):
			confirm.reauth_password(PWD)
		with self.assertRaises(BrowserSessionRequired):
			session.set_window(self.user, "reauth")
		self.assertIsNone(state.get_sudo_window(frappe.session.sid))
		self.assertFalse(session.has_management_sudo(self.user))

	def test_a_window_keyed_on_a_token_sid_is_never_honoured(self):
		# A window left on sid == user (what a token caller used to be able to mint) is
		# shared by every token credential of the user; it must read back as absent.
		state.set_sudo_window(self.user, {"v": 1, "user": self.user, "seeded_by": "reauth"}, 600)
		self.addCleanup(state.clear_sudo_window, self.user)
		self._authenticate_with_token()
		self.assertIsNone(session.get_window(self.user))
		self.assertFalse(session.has_management_sudo(self.user))
		self.assertIsNone(session.get_window(self.user, sid=self.user))

	def test_password_fallback_action_cannot_be_completed_over_a_token(self):
		fingerprint = session.payload_hash({"amount": 50})
		sign_in(self.user)
		self._request()
		token = confirm.reauth_password(PWD, action=REFUND_ACTION, payload_fingerprint=fingerprint)["grant"]

		self._authenticate_with_token()
		with self.assertRaises(BrowserSessionRequired):
			confirm.reauth_password(PWD, action=REFUND_ACTION, payload_fingerprint=fingerprint)
		frappe.local.form_dict[session.GRANT_KWARG] = token
		with self.assertRaises(BrowserSessionRequired):
			self.refund(amount=50)
		self.assertEqual(self.refund_calls, [])

	def test_browser_session_control_still_works(self):
		sign_in(self.user)
		self._request()
		self.assertTrue(confirm.reauth_password(PWD)["seeded"])
		self.assertTrue(session.has_management_sudo(self.user))
		fingerprint = session.payload_hash({"amount": 50})
		token = confirm.reauth_password(PWD, action=REFUND_ACTION, payload_fingerprint=fingerprint)["grant"]
		frappe.local.form_dict[session.GRANT_KWARG] = token
		self.assertEqual(self.refund(amount=50), 50)

	def test_test_mode_enrolment_leaves_no_window_behind(self):
		snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(flush_settings_cache)
		for field in ("login_with_passkey", "passkey_rp_id", "passkey_origins"):
			self.addCleanup(frappe.db.set_single_value, "Passkey Settings", field, snapshot.get(field))
		fake_webauthn.enable()
		frappe.set_user(self.user)
		self._request()
		registered = fake_webauthn._register_ceremony(
			"token-auth", -7, "example.com", "https://example.com", None, True
		)
		self.assertTrue(frappe.db.exists("WebAuthn Credential", registered["name"]))
		self.assertEqual(frappe.session.sid, self.user)
		self.assertIsNone(state.get_sudo_window(self.user))
