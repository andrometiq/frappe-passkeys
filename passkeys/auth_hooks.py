# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sanctioned-hook enforcement seams (folds into ``frappe``'s
own auth surface on the core merge).

**Hook-path import discipline:** ``guard_system_settings`` rides
``doc_events`` on System Settings ``validate`` — a hook that fires on every
System Settings save — so this module MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe``.

The ``on_login`` veto (``passkey_only_login``) and the sudo-window seed
(currently in ``session.py``) are the other tenants of this module in the
core-merge layout; only the two-way 2FA-floor guard is built here."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import install


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

	**Impersonation exemption** — by session state, not a marker: core's
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
	distinguishable: same-user re-auth (target == session user), or a session
	holding System Manager — the role core's SM-gated ``impersonate()`` requires.
	Every other cross-user, non-flagged login is policed.

	**No lockout** — two layers. (1) The Passkey Settings disable-guard
	refuses any settings save that would leave no passkey-capable login mode while
	any user is flagged, so an admin can't strand the whole cohort. (2) A flagged
	user who loses every passkey (the per-user strand this veto blocks email-link
	included) recovers out-of-band: a System Manager clears ``passkey_only_login``
	on the ``WebAuthn User Handle`` row (subject to the credential-count
	interlock), or the self-hoster clears that row / disables the app. Administrator
	is exempt (mirroring core's 2FA Administrator exemption), so the site owner can
	never be locked out through this veto. Exception-hardened only around the
	session-state and role reads — a genuine veto MUST propagate to abort the
	login."""
	if install.dormant():
		return  # dormant-shell: core owns the veto — silent no-op, never a throw
	target = getattr(login_manager, "user", None) if login_manager is not None else None

	# Impersonation / already-authenticated re-login: a non-Guest session at hook
	# time is exempt ONLY for same-user re-auth or a System-Manager holder (the
	# SM-gated impersonate() caller) — resume-based paths reach here with
	# frappe.session.user = the cookie holder (docstring above), so a bare
	# non-Guest exemption would let any logged-in session bypass the veto.
	try:
		current = frappe.session.user
	except Exception:
		current = None
	if current and current not in ("Guest", ""):
		if target and target == current:
			return  # same-user re-auth is never a first-factor login to police
		try:
			if "System Manager" in frappe.get_roles(current):
				return
		except Exception:
			pass  # fail closed — the veto below must still be evaluated

	# Our own passkey legs flag themselves before login_as — those always pass.
	flags = getattr(frappe.local, "flags", None)
	if flags is not None and flags.get("passkey_login"):
		return

	if not target or target in ("Guest", "Administrator", ""):
		return  # Administrator exempt (core-2FA parity); Guest/empty are not logins

	if _is_passkey_only(target):
		frappe.throw(
			_("This account signs in with a passkey. Please use your passkey to continue."),
			frappe.AuthenticationError,
		)


def _is_passkey_only(user: str) -> bool:
	"""Read the per-user flag off the ``WebAuthn User Handle`` row. A plain
	DB read — no ``webauthn`` import (this module rides the every-login hook path)."""
	return bool(frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login"))


def guard_system_settings(doc, method=None):
	"""System Settings ``validate``: the reverse half of the two-way 2FA floor.
	The Passkey Settings validator refuses enabling
	``passkey_as_second_factor`` while core ``enable_two_factor_auth`` is off;
	this guard refuses the *other* direction — flipping ``enable_two_factor_auth``
	**1 → 0** while ``passkey_as_second_factor`` is on — which would otherwise
	silently evaporate the structural backstop (direct-POST users would then walk
	through ``login()`` with a password alone while the passkey-2FA UI keeps
	working, and nobody would notice).

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
	old_value = cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth"))
	if not old_value:
		return  # already off (or a console-created desync) — not a 1→0 flip
	if not cint(frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor")):
		return  # passkey second factor not in use — no floor to protect
	frappe.throw(
		_(
			"Cannot disable Two Factor Authentication: it is the structural backstop for "
			"Passkey as Second Factor (direct password logins that bypass the passkey UI "
			"would otherwise face no second factor). Disable 'Passkey as Second Factor' in "
			"Passkey Settings first."
		),
		frappe.ValidationError,
	)
