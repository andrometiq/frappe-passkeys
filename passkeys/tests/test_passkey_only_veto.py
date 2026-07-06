# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""``passkey_only_login`` on_login veto battery (DESIGN-v1 §9.3 / F2 / F3-3).

The veto (``auth_hooks.on_login_veto``) is exactly what ``run_trigger("on_login")``
calls — ``on_login_veto(login_manager=self)`` — before ``make_session``, so these
tests drive the function directly with a controlled session/flag context (the
faithful reproduction of the hook's runtime state) and assert both the block and
every exemption. One test pins the hook is actually wired; one drives the F3-3
disable-guard that prevents lockout; one demonstrates the out-of-band recovery
escape."""

import frappe

from passkeys import auth_hooks
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class _LM:
	"""Minimal stand-in for the LoginManager the hook receives — the veto only
	reads ``.user`` (core sets it via ``login_as`` before ``post_login``)."""

	def __init__(self, user):
		self.user = user


class PasskeyOnlyVetoTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self._clear_flags)

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
		# the app's passkey legs set this flag before login_as (F3-2)
		frappe.local.flags.passkey_login = True
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_impersonation_is_exempt_via_non_guest_session(self):
		user = self._user(passkey_only=True)
		# during impersonation the request is still authenticated as the
		# impersonator (a real, non-Guest user) at on_login time — the F2 signal.
		frappe.set_user("Administrator")
		self._clear_flags()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def test_administrator_is_exempt(self):
		# never lock the site owner out through this veto (core-2FA parity): even a
		# genuinely flagged Administrator logs in with a password.
		cred = make_credential("Administrator")  # satisfies the handle ≥1 floor
		make_handle("Administrator", passkey_only_login=1)
		# Cleanups run LIFO: register credential-delete FIRST so the handle (which
		# carries passkey_only_login=1) is dropped BEFORE the last credential —
		# otherwise the §8.6 lockout interlock (correctly) refuses the delete. This
		# is the documented remediation: clear the flag before the last passkey.
		self.addCleanup(frappe.delete_doc, "WebAuthn Credential", cred.name, force=1, ignore_permissions=True)
		self.addCleanup(lambda: frappe.db.delete("WebAuthn User Handle", {"user": "Administrator"}))
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM("Administrator")))

	def test_guest_target_is_a_noop(self):
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM("Guest")))

	# ---- wiring -----------------------------------------------------------

	def test_veto_is_wired_on_the_on_login_hook(self):
		self.assertIn("passkeys.auth_hooks.on_login_veto", frappe.get_hooks("on_login"))

	# ---- no lockout: the F3-3 disable-guard -------------------------------

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
		# WebAuthn User Handle row (§9.3) — a normal login then passes the veto.
		frappe.set_user("Administrator")
		handle = frappe.db.get_value("WebAuthn User Handle", {"user": user})
		frappe.db.set_value("WebAuthn User Handle", handle, "passkey_only_login", 0)
		self._guest_context()
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LM(user)))

	def _restore_settings(self, snap):
		frappe.set_user("Administrator")
		for field in ("login_with_passkey", "passkey_as_second_factor"):
			frappe.db.set_single_value("Passkey Settings", field, snap.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
