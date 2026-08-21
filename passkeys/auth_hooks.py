# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sanctioned-hook enforcement seams (folds into ``frappe``'s
own auth surface on the core merge).

**Hook-path import discipline:** ``guard_system_settings`` rides
``doc_events`` on System Settings ``validate`` — a hook that fires on every
System Settings save — so this module MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe``."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import install, policy, state


def on_login_veto(login_manager=None, **kwargs):
	"""``on_login`` veto for ``passkey_only_login`` users.

	Blocks password, email-link (``login_via_key``) and social (OAuth) FIRST-FACTOR
	login for a user who opted into passkey-only sign-in. Enforced on the
	``on_login`` hook, which ``post_login`` fires **before** ``make_session`` on all
	three branches (develop ``auth.py:172-177``; a raising hook aborts the login
	before any session exists) — v15 has no ``before_login``, so this seam, not
	that one, is load-bearing.

	Passwordless / step-up passkey logins are exempt: the app's own passkey paths
	set ``frappe.local.flags.passkey_login`` before ``login_as`` (first-factor
	``verify_login``, the ``verify_second_factor`` password→passkey step-up, and the
	``complete_uv_setup`` repair), so a flagged user still gets in via a
	passkey.

	**Impersonation exemption** — by dispatch identity, not a marker: core's
	``impersonate()`` calls ``login_as`` and only *afterwards* ``set_impersonated``,
	so no impersonation marker exists at ``on_login`` time and ``LoginManager``
	carries none of the impersonation args. A non-Guest ``frappe.session.user`` is
	NOT by itself proof of impersonation, though: every login path other than
	``/api/method/login`` runs on a RESUMED session (``LoginManager.__init__`` →
	``make_session(resume=True)``, develop ``auth.py:135-138``), so at hook time
	``frappe.session.user`` is the COOKIE HOLDER — on ``login_via_key``/OAuth that
	may be an attacker's own throwaway session while ``login_manager.user`` is the
	victim, and a bare non-Guest exemption would hand over any ``passkey_only``
	account for the price of one email login key. Exempt only what is genuinely
	distinguishable: same-user re-auth (target == session user), or a request that
	DISPATCHED to core's exact ``impersonate`` method (RPC path plus client
	``cmd`` consistency) after its own Administrator gate has passed. Every other
	cross-user, non-flagged login is policed.

	**No lockout** — two layers. (1) The Passkey Settings disable-guard
	refuses any settings save that would leave no passkey-capable login mode while
	any user is flagged, so an admin can't strand the whole cohort. (2) A flagged
	user who loses every passkey (the per-user strand this veto blocks email-link
	included) recovers out-of-band: a System Manager clears ``passkey_only_login``
	on the ``WebAuthn User Handle`` row (subject to the credential-count
	interlock), or the self-hoster clears that row / disables the app. Administrator
	is not exempt after explicitly enrolling a passkey for second-factor use; console
	recovery remains the break-glass path. Exception-hardened only around the
	session-state read — a genuine veto MUST propagate to abort the
	login."""
	if install.dormant():
		return  # dormant-shell: core owns the veto — silent no-op, never a throw
	target = getattr(login_manager, "user", None) if login_manager is not None else None

	# Impersonation / already-authenticated re-login: a non-Guest session at hook
	# time is exempt ONLY for same-user re-auth or a request DISPATCHED to core's
	# exact impersonation method (RPC path plus client cmd consistency).
	# Resume-based paths reach here with frappe.session.user = the cookie holder
	# (docstring above), so a bare non-Guest exemption would bypass the veto.
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
	"""Read the per-user flag off the ``WebAuthn User Handle`` row. A plain
	DB read — no ``webauthn`` import (this module rides the every-login hook path)."""
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
	request = getattr(frappe.local, "request", None)
	path = getattr(request, "path", None) if request is not None else None
	if form is None or not form.get("otp"):
		return False
	if path != "/api/method/login" and form.get("cmd") != "login":
		return False
	# Core calls confirm_otp_token only while should_run_2fa() is true. Recheck
	# that policy here before consuming our marker so a concurrent role/settings
	# change cannot turn a request-shaped `otp` field into proof of verification.
	from frappe.twofactor import should_run_2fa

	if not should_run_2fa(user):
		return False
	tmp_id = form.get("tmp_id")
	if not tmp_id:
		return False
	record = state.consume_otp_fallback(str(tmp_id))
	return bool(record and record.get("user") == user)


def _is_password_reset_completion() -> bool:
	"""Allow core's reset-key flow to finish for second-factor users only when
	the request DISPATCHED to (not merely path-shaped like) ``update_password``.

	``update_password`` verifies the reset key, rotates the password, then calls
	``login_as``. The caller downgrades that login to Guest: recovery finishes but
	the reset key never mints an authenticated session. Passkey-only users still
	reach the later veto and are not exempted.
	"""
	# Reaching login_as after dispatch to update_password proves it already validated
	# its key: invalid/expired keys return before the login call. Do not trust a
	# merely matching path or a client-controlled `cmd`/`key` on another dispatch.
	return _request_is_core_method("frappe.core.doctype.user.user.update_password")


def _request_is_core_method(method_dotted_path: str) -> bool:
	"""True only when this request actually DISPATCHED to core's
	``method_dotted_path`` — the path matches a core RPC route AND no client
	``cmd`` diverted the dispatcher elsewhere. Frappe runs a truthy
	``form_dict.cmd`` (``frappe/app.py``) BEFORE any ``/api`` route, so
	``request.path`` alone is spoofable. ``not cmd or cmd == method`` is exactly
	the dispatcher's own branch condition read back here: a ``cmd`` that satisfies
	this guard is the same string ``execute_cmd`` dispatches on, so it provably ran
	that method (and, for impersonate, its ``only_for('Administrator')`` gate).
	Exact string compare, no normalization — fail-closed and dispatch-exact.
	(A site that remaps this dotted path via ``override_whitelisted_methods`` is a
	pre-existing server-config trust, out of scope; it applies to the reset path too.)"""
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
	"""System Settings ``validate``: the reverse half of the two-way 2FA floor.
	The Passkey Settings validator refuses enabling
	``passkey_as_second_factor`` while core ``enable_two_factor_auth`` is off;
	this guard refuses the *other* direction — flipping ``enable_two_factor_auth``
	**1 → 0** while ``passkey_as_second_factor`` is on — which would silently
	evaporate the required defence-in-depth backstop. The final login veto still
	fails closed for enrolled users, but the configuration would be unsupported.

	Only the genuine 1→0 transition is blocked: an already-off value staying off
	cannot make the floor any weaker, and blocking every save on an
	already-desynced site (a raw ``db_set``/console edit — console-bypass
	posture) would deadlock System Settings entirely. The runtime desync that a
	console edit can still create is surfaced by the leg-1 daily observation log
	(``passkeys.passkey``)."""
	if install.dormant():
		return  # dormant-shell: core owns the 2FA floor — silent no-op
	new_value = cint(doc.enable_two_factor_auth)
	if new_value:
		return  # staying on / turning on — nothing to guard
	old_value = policy.lock_core_2fa_floor()
	if not old_value:
		return  # already off (or a console-created desync) — not a 1→0 flip
	if not cint(frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor")):
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
