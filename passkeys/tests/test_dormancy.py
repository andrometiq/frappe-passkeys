# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""CORE_NATIVE dormant-shell coverage (DESIGN-v1 §11).

Once core serves passkeys natively (``install.is_core_native`` → True) the app is
a clean no-op so the two implementations never fight: EVERY whitelisted endpoint
raises the typed 417 ``PasskeyServedByCore``, EVERY hook silently no-ops (never a
raise — a hook that throws would break core logins), and a one-time uninstall
advisory fires exactly once. Nativeness is faked exactly as the install battery
does (``test_install.py``): patch ``passkeys.install.is_core_native`` — the single
switch every guard reads through ``install.dormant``."""

import frappe
from frappe.utils import cint
from unittest.mock import patch

import passkeys.confirm as confirm
from passkeys import auth_hooks, boot, install, passkey, session, state
from passkeys.api import credentials, registration
from passkeys.passkey import PasskeyServedByCore
from passkeys.shims import login_page
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


def _core_native():
	"""Fake a passkey-native core — the same switch (``passkeys.install.is_core_native``)
	the §14 install battery patches; every guard reads it through ``install.dormant``."""
	return patch("passkeys.install.is_core_native", return_value=True)


class _LM:
	"""Minimal LoginManager stand-in (the veto only reads ``.user``)."""

	def __init__(self, user):
		self.user = user


def _seed_advisory_flag():
	"""Pre-set the one-time advisory cache flag so the dormancy assertions in this
	class don't each write an Error Log — the advisory's own behaviour is pinned by
	:class:`DormantAdvisoryTest`."""
	frappe.cache.set(frappe.cache.make_key(install._DORMANT_ADVISORY_KEY), "1")


# ===========================================================================
# (a) every whitelisted endpoint 417s — one representative from EACH module
# ===========================================================================


class DormantEndpointsTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		_seed_advisory_flag()
		self.addCleanup(frappe.cache.delete_value, install._DORMANT_ADVISORY_KEY)
		self.addCleanup(frappe.set_user, "Administrator")

	def _assert_417(self, fn, *args, **kwargs):
		with _core_native():
			with self.assertRaises(PasskeyServedByCore) as ctx:
				fn(*args, **kwargs)
		self.assertEqual(ctx.exception.http_status_code, 417)

	# passkey.py — login / 2FA / uv-setup / signal / nudge / translations legs
	def test_login_leg_refused(self):
		self._assert_417(passkey.begin_login)

	def test_verify_login_leg_refused(self):
		self._assert_417(passkey.verify_login, "state", {"id": "x"})

	def test_second_factor_leg_refused(self):
		self._assert_417(passkey.login_with_password, "user@example.com", "pw")

	def test_verify_second_factor_refused(self):
		self._assert_417(passkey.verify_second_factor, "state", {"id": "x"})

	def test_fallback_to_otp_refused(self):
		self._assert_417(passkey.fallback_to_otp, "state")

	def test_uv_setup_refused(self):
		self._assert_417(passkey.complete_uv_setup, "setup", "pw")

	def test_signal_data_refused(self):
		self._assert_417(passkey.get_signal_data)

	def test_record_nudge_refused(self):
		self._assert_417(passkey.record_nudge, "shown")

	def test_translations_refused(self):
		self._assert_417(passkey.get_app_translations)

	# api/registration.py
	def test_begin_registration_refused(self):
		self._assert_417(registration.begin_registration)

	def test_verify_registration_refused(self):
		self._assert_417(registration.verify_registration, "state", {"id": "x"})

	# api/credentials.py — list / rename / delete / passkey-only switch
	def test_credentials_list_refused(self):
		self._assert_417(credentials.list_credentials)

	def test_credentials_rename_refused(self):
		self._assert_417(credentials.rename_credential, "name", "label")

	def test_credentials_delete_refused(self):
		self._assert_417(credentials.delete_credential, "name")

	def test_set_passkey_only_login_refused(self):
		self._assert_417(credentials.set_passkey_only_login, 1)

	# confirm.py — the action-signing surface (already guarded pre-S2; pinned here)
	def test_confirm_begin_refused(self):
		self._assert_417(confirm.begin_confirmation, "act")

	def test_confirm_verify_refused(self):
		self._assert_417(confirm.verify_confirmation, "state", {"id": "x"})

	def test_confirm_reauth_password_refused(self):
		self._assert_417(confirm.reauth_password, "pw")


# ===========================================================================
# (b) every hook silently no-ops (never raises) — with a live control that
#     proves the guard is what silences a would-be throw / write
# ===========================================================================


class DormantHooksTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		_seed_advisory_flag()
		self.addCleanup(frappe.cache.delete_value, install._DORMANT_ADVISORY_KEY)
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self._clear_flags)

	def _clear_flags(self):
		if getattr(frappe.local, "flags", None) is not None:
			frappe.local.flags.pop("passkey_login", None)

	def _user(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def test_on_login_veto_noop_instead_of_throwing(self):
		user = self._user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)
		frappe.set_user("Guest")  # genuine first-factor context
		self._clear_flags()
		# control: the veto really fires without the switch
		with self.assertRaises(frappe.AuthenticationError):
			auth_hooks.on_login_veto(login_manager=_LM(user))
		# dormant: silent pass, no throw
		with _core_native():
			self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_guard_system_settings_noop_instead_of_throwing(self):
		orig_2fa = cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth"))
		self.addCleanup(frappe.db.set_single_value, "System Settings", "enable_two_factor_auth", orig_2fa)
		self.addCleanup(frappe.db.set_single_value, "Passkey Settings", "passkey_as_second_factor", 0)
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 1)
		doc = frappe._dict(enable_two_factor_auth=0)  # the disallowed 1→0 flip
		# control: the floor guard really fires
		with self.assertRaises(frappe.ValidationError):
			auth_hooks.guard_system_settings(doc)
		# dormant: silent pass
		with _core_native():
			self.assertIsNone(auth_hooks.guard_system_settings(doc))

	def test_seed_sudo_window_writes_nothing(self):
		user = self._user()
		frappe.set_user(user)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		# control: a normal login seeds a window
		session.seed_sudo_window(login_manager=_LM(user))
		self.assertIsNotNone(state.get_sudo_window(frappe.session.sid))
		state.clear_sudo_window(frappe.session.sid)
		# dormant: nothing seeded
		with _core_native():
			session.seed_sudo_window(login_manager=_LM(user))
		self.assertIsNone(state.get_sudo_window(frappe.session.sid))

	def test_clear_sudo_window_is_a_noop(self):
		user = self._user()
		frappe.set_user(user)
		self.addCleanup(state.clear_sudo_window, frappe.session.sid)
		state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
		# dormant: the window is left intact (core owns logout teardown)
		with _core_native():
			session.clear_sudo_window(login_manager=_LM(user))
		self.assertIsNotNone(state.get_sudo_window(frappe.session.sid))

	def test_extend_bootinfo_publishes_nothing(self):
		user = self._user()
		make_credential(user)
		frappe.set_user(user)
		info = frappe._dict()
		with _core_native():
			boot.extend_bootinfo(bootinfo=info)
		# no bootinfo.passkeys ⇒ the desk/portal bundles self-remove on the absent
		# `frappe.boot.passkeys.enabled` flag (§11 client self-removal)
		self.assertIsNone(info.get("passkeys"))

	def test_website_context_appends_no_login_bundle(self):
		orig = cint(frappe.db.get_single_value("Passkey Settings", "login_with_passkey"))

		def _restore():
			frappe.db.set_single_value("Passkey Settings", "login_with_passkey", orig)
			frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

		self.addCleanup(_restore)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		# control: with a mode on, the shim appends the login bundle on /login
		ctrl = frappe._dict(path="login")
		login_page.website_context(ctrl)
		self.assertTrue(any("passkey_login" in a for a in ctrl.get("web_include_js", [])))
		# dormant: nothing appended (the /login page ships zero passkey bytes)
		context = frappe._dict(path="login")
		with _core_native():
			login_page.website_context(context)
		self.assertNotIn("web_include_js", context)

	def test_cascade_delete_is_a_noop(self):
		user = self._user()
		make_credential(user)
		make_handle(user)
		# dormant: rows survive (core owns the on_trash cascade — no double delete)
		with _core_native():
			passkey.cascade_delete_user_artifacts(frappe._dict(name=user))
		self.assertTrue(frappe.db.exists("WebAuthn Credential", {"user": user}))
		self.assertTrue(frappe.db.exists("WebAuthn User Handle", {"user": user}))

	def test_cascade_delete_removes_rows_when_active(self):
		user = self._user()
		make_credential(user)
		make_handle(user)
		# control: the cascade really deletes when the app is live
		passkey.cascade_delete_user_artifacts(frappe._dict(name=user))
		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": user}))
		self.assertFalse(frappe.db.exists("WebAuthn User Handle", {"user": user}))


# ===========================================================================
# (c) the one-time uninstall advisory fires exactly once
# ===========================================================================


class DormantAdvisoryTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		# clear the flag so THIS test controls the fire
		frappe.cache.delete_value(install._DORMANT_ADVISORY_KEY)
		self.addCleanup(frappe.cache.delete_value, install._DORMANT_ADVISORY_KEY)
		self.addCleanup(frappe.set_user, "Administrator")

	def test_advisory_fires_once_across_many_dormant_hits(self):
		with _core_native():
			with patch.object(frappe, "log_error") as mock_log:
				self.assertTrue(install.dormant())  # first engagement → advisory
				self.assertTrue(install.dormant())  # cached → silent
				try:
					passkey.begin_login()  # endpoint guard → dormant()
				except PasskeyServedByCore:
					pass
				auth_hooks.on_login_veto(login_manager=_LM("Guest"))  # hook guard → dormant()
		advisory = [
			call
			for call in mock_log.call_args_list
			if "dormant" in str(call.kwargs.get("title", "")).lower()
		]
		self.assertEqual(len(advisory), 1)

	def test_advisory_never_fires_when_core_is_not_native(self):
		# on a normal (non-native) bench dormant() is False and logs nothing
		with patch.object(frappe, "log_error") as mock_log:
			self.assertFalse(install.dormant())
		advisory = [
			call
			for call in mock_log.call_args_list
			if "dormant" in str(call.kwargs.get("title", "")).lower()
		]
		self.assertEqual(advisory, [])
