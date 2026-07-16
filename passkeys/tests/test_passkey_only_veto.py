# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""``passkey_only_login`` on_login veto battery.

The veto (``auth_hooks.on_login_veto``) is exactly what ``run_trigger("on_login")``
calls — ``on_login_veto(login_manager=self)`` — before ``make_session``, so these
tests drive the function directly with a controlled session/flag context (the
faithful reproduction of the hook's runtime state) and assert both the block and
every exemption. One test pins the hook is actually wired; one drives the
disable-guard that prevents lockout; one demonstrates the out-of-band recovery
escape."""

import frappe

from passkeys import auth_hooks
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user


class _LM:
	"""Minimal stand-in for the LoginManager the hook receives — the veto only
	reads ``.user`` (core sets it via ``login_as`` before ``post_login``)."""

	def __init__(self, user):
		self.user = user


class PasskeyOnlyVetoTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._mode_snapshot = (
			frappe.db.get_single_value("Passkey Settings", "login_with_passkey"),
			frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor"),
		)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		flush_settings_cache()
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self._clear_flags)

	def tearDown(self):
		# The framework has NO per-test rollback (isolation is per-class, and only for
		# UNCOMMITTED rows). A leg here can leave a COMMITTED passkey_only handle — a
		# mid-test role/permission write commits, making the row durable past the class
		# rollback. Force-sweep the passkey_only rows this battery creates (incl. the
		# Administrator handle) and commit, so a stray passkey_only row can never leak into
		# a later module's last-login-method guard (which lists it and refuses the save).
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		frappe.db.delete("WebAuthn Credential", {"user": "Administrator"})
		frappe.db.delete("WebAuthn User Handle", {"user": "Administrator"})
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", self._mode_snapshot[0] or 0)
		frappe.db.set_single_value(
			"Passkey Settings", "passkey_as_second_factor", self._mode_snapshot[1] or 0
		)
		flush_settings_cache()
		frappe.db.commit()  # must survive past the (per-class) rollback

	def _clear_flags(self):
		if getattr(frappe.local, "flags", None) is not None:
			frappe.local.flags.pop("passkey_login", None)

	def _user(self, *, passkey_only=False) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		make_credential(user)
		make_handle(user, passkey_only_login=1 if passkey_only else 0)
		return user

	def _guest_context(self):
		"""Every genuine first-factor login runs with a Guest session at hook time."""
		frappe.set_user("Guest")
		self._clear_flags()

	# ---- the block --------------------------------------------------------

	def test_password_login_blocked_for_passkey_only_user(self):
		user = self._user(passkey_only=True)
		self._guest_context()
		with self.assertRaises(frappe.AuthenticationError):
			auth_hooks.on_login_veto(login_manager=_LM(user))

	def test_email_link_and_social_are_blocked_too(self):
		# email-link / social reach on_login as a Guest session with NO
		# passkey_login flag — indistinguishable from password here, all blocked.
		user = self._user(passkey_only=True)
		self._guest_context()
		with self.assertRaises(frappe.AuthenticationError):
			auth_hooks.on_login_veto(login_manager=_LM(user))

	# ---- exemptions -------------------------------------------------------

	def test_non_passkey_only_user_passes(self):
		user = self._user(passkey_only=False)
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_passwordless_passkey_login_passes(self):
		user = self._user(passkey_only=True)
		self._guest_context()
		# the app's passkey legs set this flag before login_as
		frappe.local.flags.passkey_login = True
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_impersonation_is_exempt_via_non_guest_session(self):
		user = self._user(passkey_only=True)
		# during impersonation the request is still authenticated as the
		# impersonator (a real, non-Guest user) at on_login time — the signal.
		frappe.set_user("Administrator")
		self._clear_flags()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_administrator_is_exempt(self):
		# never lock the site owner out through this veto (core-2FA parity): even a
		# genuinely flagged Administrator logs in with a password.
		cred = make_credential("Administrator")  # satisfies the handle ≥1 floor
		make_handle("Administrator", passkey_only_login=1)
		# Teardown must not be subject to the last-login-method guard: deleting the
		# last enabled credential of a passkey-only (or disable_user_pass_login)
		# account is correctly refused by on_trash, and that account state can leak
		# in from another test on some Frappe versions. Tear down with raw db.delete,
		# which bypasses the on_trash hook exactly as the User-delete cascade does.
		self.addCleanup(lambda: frappe.db.delete("WebAuthn Credential", {"name": cred.name}))
		self.addCleanup(lambda: frappe.db.delete("WebAuthn User Handle", {"user": "Administrator"}))
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM("Administrator")))

	def test_guest_target_is_a_noop(self):
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM("Guest")))

	# ---- resumed-session takeover (SEC-1) ---------------------------------

	def test_resumed_attacker_session_cannot_bypass_veto(self):
		"""SEC-1 regression: ``login_via_key``/OAuth run on a RESUMED session, so
		``frappe.session.user`` at on_login time is the COOKIE HOLDER — an
		attacker's own throwaway session redeeming a passkey_only victim's
		one-time email key must still be vetoed (a bare non-Guest exemption was
		full account takeover)."""
		victim = self._user(passkey_only=True)
		attacker = self._user(passkey_only=False)
		frappe.set_user(attacker)  # the resumed-session state login_via_key leaves
		self._clear_flags()
		with self.assertRaises(frappe.AuthenticationError):
			auth_hooks.on_login_veto(login_manager=_LM(victim))

	def test_same_user_reauth_is_still_exempt(self):
		user = self._user(passkey_only=True)
		frappe.set_user(user)  # already authenticated as themselves
		self._clear_flags()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_system_manager_session_is_still_exempt(self):
		# the SM-gated impersonate() caller — a non-Administrator SM.
		victim = self._user(passkey_only=True)
		manager = self._user(passkey_only=False)
		frappe.get_doc("User", manager).add_roles("System Manager")
		frappe.set_user(manager)
		self._clear_flags()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(victim)))

	def test_flagged_passkey_login_passes_over_a_resumed_foreign_session(self):
		# the app's own passkey legs (flag set before login_as) still pass
		# when a different user's session is being resumed on the same browser.
		victim = self._user(passkey_only=True)
		other = self._user(passkey_only=False)
		frappe.set_user(other)
		frappe.local.flags.passkey_login = True
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(victim)))

	# ---- wiring -----------------------------------------------------------

	def test_veto_is_wired_on_the_on_login_hook(self):
		self.assertIn("passkeys.auth_hooks.on_login_veto", frappe.get_hooks("on_login"))

	# ---- no lockout: the disable-guard -------------------------------

	def test_disable_guard_blocks_removing_the_last_passkey_mode(self):
		user = self._user(passkey_only=True)
		snap = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(self._restore_settings, snap)
		settings = frappe.get_doc("Passkey Settings")
		settings.login_with_passkey = 0
		settings.passkey_as_second_factor = 0
		with self.assertRaises(frappe.ValidationError):
			settings.save(ignore_permissions=True)
		self.assertIn(
			user, frappe.get_all("WebAuthn User Handle", filters={"passkey_only_login": 1}, pluck="user")
		)

	# ---- recovery escape --------------------------------------------------

	def test_recovery_by_clearing_the_flag_restores_login(self):
		user = self._user(passkey_only=True)
		self._guest_context()
		with self.assertRaises(frappe.AuthenticationError):
			auth_hooks.on_login_veto(login_manager=_LM(user))
		# out-of-band recovery: a System Manager clears the per-user flag on the
		# WebAuthn User Handle row — a normal login then passes the veto.
		frappe.set_user("Administrator")
		handle = frappe.db.get_value("WebAuthn User Handle", {"user": user})
		frappe.db.set_value("WebAuthn User Handle", handle, "passkey_only_login", 0)
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def _restore_settings(self, snap):
		frappe.set_user("Administrator")
		for field in ("login_with_passkey", "passkey_as_second_factor"):
			frappe.db.set_single_value("Passkey Settings", field, snap.get(field) or 0)
		flush_settings_cache()
