# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sanctioned-hook enforcement seams (fold into core's own auth surface on the merge):
the final login veto and the System Settings guard. On the every-login and every
System Settings save paths, so this module must not import ``webauthn``."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import install, policy, state
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import lock_passkey_modes


def on_login_veto(login_manager=None, **kwargs):
	"""``on_login`` veto, fired before ``make_session`` on every stock login path (v15 has
	no ``before_login``): enrolled second-factor users must finish the passkey (or the
	app-issued OTP fallback) leg, and ``passkey_only_login`` users need a passkey. The
	app's own passkey legs set ``flags.passkey_login`` and pass.

	Impersonation is recognised by dispatch identity, not by a non-Guest session: on the
	resumed-session paths (email link, OAuth) ``frappe.session.user`` is the cookie
	holder, possibly an attacker, while ``login_manager.user`` is the victim. Only
	same-user re-auth and a request dispatched to core's ``impersonate`` (which has its
	own Administrator gate) are exempt. Recovery for a stranded user: docs/recovery.md."""
	if install.dormant():
		return
	target = getattr(login_manager, "user", None) if login_manager is not None else None

	try:
		current = frappe.session.user
	except Exception:
		current = None
	if current and current not in ("Guest", ""):
		if target and target == current:
			return  # same-user re-auth is never a first-factor login to police
		if _request_is_core_method("frappe.core.doctype.user.user.impersonate"):
			return

	# Our own passkey legs flag themselves before login_as — those always pass.
	flags = getattr(frappe.local, "flags", None)
	if flags is not None and flags.get("passkey_login"):
		return

	if not target or target in ("Guest", ""):
		return  # Guest/empty are not logins

	if _must_use_passkey_second_factor(target):
		if _is_password_reset_completion():
			# Core rotates the password and then calls login_as(). Let the reset
			# transaction finish, but downgrade that login_as() to Guest so possession
			# of an emailed reset key never satisfies the passkey second factor.
			login_manager.user = "Guest"
		elif not _consume_allowed_otp_fallback(target):
			frappe.throw(
				_(
					"This account requires a passkey after the password. Please sign in from the passkey login form."
				),
				frappe.AuthenticationError,
			)

	# Preserve the existing passkey-only break-glass exemption. An Administrator
	# who explicitly enrolled a second-factor credential was handled above.
	if target == "Administrator":
		return

	if _is_passkey_only(target):
		frappe.throw(
			_("This account signs in with a passkey. Please use your passkey to continue."),
			frappe.AuthenticationError,
		)


def _is_passkey_only(user: str) -> bool:
	"""The per-user flag on the ``WebAuthn User Handle`` row."""
	return bool(frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login"))


def _must_use_passkey_second_factor(user: str) -> bool:
	"""Whether a stock password login must be vetoed for this enrolled user."""
	if not cint(frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor")):
		return False
	return bool(frappe.db.exists("WebAuthn Credential", {"user": user, "enabled": 1}))


def _consume_allowed_otp_fallback(user: str) -> bool:
	"""Accept only the core OTP completion issued by ``fallback_to_otp``.

	The marker alone is not proof that OTP ran: alternate login endpoints preserve
	request parameters, so an email-link/OAuth request could otherwise carry a stolen
	``tmp_id`` into this hook. Core has already verified ``otp`` when this hook runs,
	but only on its own login route.
	"""
	form = getattr(frappe.local, "form_dict", None)
	if form is None or not form.get("otp"):
		return False
	from passkeys.session import _is_core_password_login

	if not _is_core_password_login():
		return False
	tmp_id = form.get("tmp_id")
	if not tmp_id:
		return False
	tmp_id = str(tmp_id)
	record = state.get_otp_fallback(tmp_id)
	if not record or record.get("user") != user:
		return False
	# Core calls confirm_otp_token only while should_run_2fa() is true. Recheck
	# that policy here before consuming our marker so a concurrent role/settings
	# change cannot turn a request-shaped `otp` field into proof of verification.
	from frappe.twofactor import should_run_2fa

	if not should_run_2fa(user):
		return False
	consumed = state.consume_otp_fallback(tmp_id)
	return bool(consumed and consumed.get("user") == user)


def _is_password_reset_completion() -> bool:
	"""The request dispatched to core's ``update_password``, which validates the reset
	key before its ``login_as``. The caller downgrades that login to Guest, so a reset key
	never mints a session; passkey-only users still reach the later veto."""
	return _request_is_core_method("frappe.core.doctype.user.user.update_password")


def _request_is_core_method(method_dotted_path: str) -> bool:
	"""This request actually dispatched to core's ``method_dotted_path``. Frappe runs a
	truthy ``form_dict.cmd`` before any ``/api`` route, so the path alone is spoofable;
	``not cmd or cmd == method`` is the dispatcher's own branch condition, compared
	exactly."""
	request = getattr(frappe.local, "request", None)
	path = getattr(request, "path", None) if request is not None else None
	if not isinstance(path, str):
		return False
	if path.rstrip("/") not in (
		f"/api/method/{method_dotted_path}",
		f"/api/v1/method/{method_dotted_path}",
		f"/api/v2/method/{method_dotted_path}",
	):
		return False
	form = getattr(frappe.local, "form_dict", None)
	cmd = form.get("cmd") if form is not None else None
	return not cmd or cmd == method_dotted_path


def guard_system_settings(doc, method=None):
	"""System Settings ``validate``, the reverse half of the Passkey Settings floors:
	refuse turning core 2FA off while Passkey as Second Factor is on, and refuse
	disabling password login while that is the only passkey mode. Only a real 1→0 / 0→1
	flip is refused, so a console-created desync never deadlocks System Settings (the
	posture panel flags it). Values are read under row locks (docs/security.md)."""
	if install.dormant():
		return
	if not cint(doc.disable_user_pass_login) and cint(doc.enable_two_factor_auth):
		return  # neither floor can weaken
	modes = lock_passkey_modes()
	_guard_password_login_floor(doc, modes)
	_guard_two_factor_floor(doc, modes)


def _guard_password_login_floor(doc, modes) -> None:
	if not cint(doc.disable_user_pass_login):
		return
	if policy.lock_system_setting("disable_user_pass_login"):
		return  # already on — not a 0→1 flip
	if not modes.passkey_as_second_factor or modes.login_with_passkey:
		return
	frappe.throw(
		_(
			"Cannot disable username/password login while Passkey as Second Factor is the only passkey mode: enrolled users would have no way to sign in. Enable Login with Passkey or turn off Passkey as Second Factor in Passkey Settings first."
		),
		frappe.ValidationError,
	)


def _guard_two_factor_floor(doc, modes) -> None:
	if cint(doc.enable_two_factor_auth):
		return  # staying on / turning on — nothing to guard
	if not policy.lock_system_setting("enable_two_factor_auth"):
		return  # already off (or a console-created desync) — not a 1→0 flip
	if not modes.passkey_as_second_factor:
		return  # passkey second factor not in use — no floor to protect
	frappe.throw(
		_(
			"Cannot disable Two Factor Authentication: it is the structural backstop for "
			"Passkey as Second Factor. The final login veto remains fail-closed, but the "
			"required defence-in-depth floor would be lost. Disable 'Passkey as Second Factor' in "
			"Passkey Settings first."
		),
		frappe.ValidationError,
	)
