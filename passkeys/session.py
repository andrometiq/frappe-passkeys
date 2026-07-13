# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sudo-window semantics + the passkey-grant consumer
used by the management surface. Folds into ``frappe/passkey.py`` on the core
merge.

**Hook-path import discipline:** this module sits on the
``on_session_creation`` / ``on_logout`` hook chains — which fire on *every*
login/logout of *every* user — so it MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe`` and :mod:`passkeys.state`.

Placement note: the sudo seed + check live here in ``session.py`` (not
``auth_hooks.py``) to keep this hook-path file import-clean. ``hooks.py`` points
the hooks here.
"""

import hashlib
import json

import frappe
from frappe import _
from frappe.utils import cint, now

from passkeys import install, state

# Built-in action for the app's own management surface.
MANAGE_ACTION = "passkeys.manage"
SET_PASSKEY_ONLY_ACTION = "passkeys.set_passkey_only_login"

# Seeding classes. ``password``/``passkey``/``reauth`` grant a full sudo
# window; ``weak`` (email-link / OAuth / social) seeds a window that only the
# restricted first-enrollment bootstrap honours — never general management.
FULL_SUDO_METHODS = ("password", "passkey", "reauth")

GRANT_HEADER = "X-Passkey-Grant"
GRANT_KWARG = "_passkey_grant"


# ---------------------------------------------------------------------------
# on_session_creation seed — fires after make_session inside post_login,
# where the sid already exists (the on_login veto fires BEFORE make_session
# and cannot seed a sid-keyed window).
# ---------------------------------------------------------------------------


def seed_sudo_window(login_manager=None, **kwargs) -> None:
	"""Seed a sudo window for the freshly-created session, classified by login
	method. Exception-hardened: a failure here must never take down a
	login (this hook runs on every login of every user)."""
	try:
		if install.dormant():
			return  # dormant-shell: core owns sudo seeding — silent no-op
		user = frappe.session.user
		if not user or user in ("Guest", ""):
			return
		method = _classify_login_method()
		if method is None:
			return
		settings = frappe.get_cached_doc("Passkey Settings")
		ttl = cint(settings.passkey_reauth_window) or 600
		state.set_sudo_window(
			frappe.session.sid,
			{"v": 1, "user": user, "seeded_by": method},
			ttl,
		)
		_maybe_record_password_login_risk(user, method, settings)
	except Exception:
		frappe.log_error(title="passkeys: sudo-window seed failed")


def _maybe_record_password_login_risk(user: str, method: str, settings) -> None:
	"""``password_login_by_passkey_holder`` risk event: a user who holds ≥1
	enabled passkey signed in with their password instead. Opt-in behind
	``passkey_notify_password_login`` (default OFF) — so the enabled-credential
	read never touches the hot login path unless an operator wants the telemetry,
	and a default site records nothing. Best-effort — the enclosing seed is already
	exception-hardened; a telemetry failure must never break a login."""
	if method != "password":
		return
	if not cint(getattr(settings, "passkey_notify_password_login", 0)):
		return
	if not frappe.db.exists("WebAuthn Credential", {"user": user, "enabled": 1}):
		return
	from passkeys import notifications

	notifications.record_risk_event(
		notifications.RISK_PASSWORD_LOGIN_BY_PASSKEY_HOLDER,
		user,
		f"Password login by passkey holder {user}",
	)


def clear_sudo_window(login_manager=None, **kwargs) -> None:
	"""on_logout: drop this session's sudo window. Exception-hardened."""
	try:
		if install.dormant():
			return  # dormant-shell: core owns logout teardown — silent no-op
		sid = frappe.session.sid
		if sid:
			state.clear_sudo_window(sid)
	except Exception:
		frappe.log_error(title="passkeys: sudo-window clear failed")


def _classify_login_method() -> str | None:
	"""Best-available classification at ``on_session_creation`` time:

	* ``passkey`` — the app's own passwordless / passkey-2FA / uv-setup legs set
	  ``frappe.local.flags.passkey_login`` before ``login_as``.
	* ``password`` — a core username+password login (the ``/api/method/login``
	  endpoint, or the v15/v16 ``cmd=login`` trigger), where a password was
	  verified by ``authenticate``; ALSO the app's own plain-password arm
	  (``login_with_password``'s LDAP-style finish for a passkey-less, 2FA-less
	  user), which sets ``frappe.local.flags.passkeys_password_login`` — its
	  endpoint path is not ``/api/method/login``, so without the flag the
	  core-path heuristic below would mis-classify a real password login as
	  ``weak`` and re-fire the conditional-create nudge.
	* ``weak`` — anything else that reached a real (non-Guest) session via
	  ``login_as``: email-link (``login_via_key``), OAuth / social.

	LDAP (which verifies a password but reaches ``post_login`` off its own
	endpoint path) currently falls into ``weak`` — the conservative direction
	(under-grant: LDAP users get only first-enrollment bootstrap, not general
	sudo). Tightening that is deferred to the LDAP-integration phase.
	"""
	flags = getattr(frappe.local, "flags", None)
	if flags is not None and flags.get("passkey_login"):
		return "passkey"
	if flags is not None and flags.get("passkeys_password_login"):
		return "password"
	if _is_core_password_login():
		return "password"
	return "weak"


def _is_core_password_login() -> bool:
	request = getattr(frappe.local, "request", None)
	if request is not None and getattr(request, "path", None) == "/api/method/login":
		return True
	form = getattr(frappe.local, "form_dict", None)
	# v15/v16 additionally trigger core login on cmd=login (login-trigger row).
	return bool(form is not None and form.get("cmd") == "login")


# ---------------------------------------------------------------------------
# check helpers (consumers)
# ---------------------------------------------------------------------------


def get_window(user: str, sid: str | None = None) -> dict | None:
	"""The live sudo window for ``user`` on ``sid`` (Redis ``ex`` is the sole
	expiry authority — an expired window reads back as ``None``). Returns
	``None`` when absent or owned by a different user."""
	sid = sid or frappe.session.sid
	window = state.get_sudo_window(sid)
	if not window or window.get("user") != user:
		return None
	return window


def has_management_sudo(user: str, sid: str | None = None) -> bool:
	"""True iff a full-sudo window (password / passkey / reauth-seeded) is live
	for the user. A ``weak``-seeded window does NOT satisfy management —
	recovery-grade logins never silently mint management power."""
	window = get_window(user, sid)
	return bool(window and window.get("seeded_by") in FULL_SUDO_METHODS)


def require_authed_user() -> str:
	"""The current session user, or raise ``AuthenticationError`` for Guest/empty.
	The shared authenticated-user guard the confirm / registration / credentials
	endpoints front their handlers with."""
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	return user


def require_management_sudo(user: str) -> None:
	"""Gate the app's management surface. Raises the typed
	``PasskeyConfirmationRequired`` retry contract when no full-sudo
	window is live — the client then runs a passkey confirmation (or password
	re-auth), which re-seeds the window."""
	if has_management_sudo(user):
		return
	_raise_confirmation_required(MANAGE_ACTION, methods=["passkey", "password", "sudo"])


# ---------------------------------------------------------------------------
# passkey-grant consumer — the consumer half of the action-signing primitive
# (the minter is confirm.begin_confirmation / verify_confirmation + the
# @passkey_protected decorator).
# ---------------------------------------------------------------------------


def canonical_json(payload: dict) -> str:
	"""Pinned server-only canonicalization. JS never computes a hash."""
	return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(params: dict) -> str:
	return hashlib.sha256(canonical_json(params).encode("utf-8")).hexdigest()


def consume_passkey_grant(user: str, action: str, params: dict) -> bool:
	"""Atomically consume a single-use **passkey-method** grant bound to
	user + sid + action + exact payload. Returns ``True`` on a
	valid consume, ``False`` otherwise (missing token, wrong owner/sid/action,
	payload mismatch, or a password-minted grant). Never accepts a sudo window
	or a password-minted grant — the threat model ("the password is not
	sufficient")."""
	token = _grant_token()
	if not token:
		return False
	record = state.consume_grant(hashlib.sha256(token.encode("utf-8")).hexdigest())
	if not record:
		return False
	return _grant_matches(record, user, action, params) and record.get("method") == "passkey"


def _grant_matches(record: dict, user: str, action: str, params: dict) -> bool:
	"""Ownership/binding predicate shared by both grant consumers: a grant
	authorizes only its exact ``user`` + current sid + declared ``action`` +
	exact payload. Method binding is layered by the caller."""
	return (
		record.get("user") == user
		and record.get("sid") == frappe.session.sid
		and record.get("action") == action
		and record.get("payload_hash") == payload_hash(params)
	)


def mint_action_grant(
	user: str,
	action: str,
	payload_hash_hex: str,
	*,
	method: str,
	sid: str | None = None,
	ttl: int | None = None,
) -> str:
	"""Mint a single-use action grant and return the raw token **once**.

	The token is stored only as SHA-256 (a cache snapshot never yields a usable
	grant); the record binds ``user + sid + action + payload_hash + method`` and
	expires by Redis ``ex`` alone (default 180 s ≤ the pinned cap). ``method`` is
	``"passkey"`` (a real UV assertion via the confirm ceremony) or ``"password"``
	(a ``reauth_password`` action-grant, accepted only by
	``allow_password_fallback`` actions — never by set_passkey_only_login).
	``payload_hash_hex`` is the ceremony's stored hash (server-computed from raw
	params at ``begin_confirmation``, or the verbatim echoed fingerprint), NOT raw
	params."""
	token = frappe.generate_hash()
	state.store_grant(
		hashlib.sha256(token.encode("utf-8")).hexdigest(),
		{
			"v": 1,
			"user": user,
			"sid": sid or frappe.session.sid,
			"action": action,
			"payload_hash": payload_hash_hex,
			"method": method,
			"at": now(),
		},
		ttl if ttl is not None else state.GRANT_TTL,
	)
	_audit_grant("issued", action, user, method)
	return token


def consume_action_grant(
	user: str,
	action: str,
	params: dict,
	*,
	allow_password_fallback: bool = False,
	allow_sudo_window: bool = False,
) -> bool:
	"""Generalized grant consumer for the public ``@passkey_protected`` decorator
	Atomically consumes a presented grant bound to
	user + sid + action + exact payload:

	* a ``passkey``-method grant always satisfies the gate;
	* a ``password``-method grant satisfies it **only** when the action declared
	  ``allow_password_fallback=True`` (the primitive's universal-re-auth mode);
	* when no matching grant token is presented and ``allow_sudo_window=True``, a
	  live full-sudo window (GitHub-sudo ergonomics for the app's own management)
	  satisfies it instead.

	Returns ``True`` on a valid consume, else ``False`` (caller raises the 401
	retry contract). Unlike :func:`consume_passkey_grant` (the strict gate),
	this honours the per-action fallback policy — but the invariant still
	holds structurally: set_passkey_only_login is declared
	``allow_password_fallback=False``, so a password-method grant is rejected here
	AND :func:`consume_passkey_grant` refuses any non-passkey method outright."""
	token = _grant_token()
	if token:
		record = state.consume_grant(hashlib.sha256(token.encode("utf-8")).hexdigest())
		if record and _grant_matches(record, user, action, params):
			method = record.get("method")
			if method == "passkey":
				_audit_grant("consumed", action, user, method)
				return True
			if method == "password" and allow_password_fallback:
				_audit_grant("consumed", action, user, method)
				return True
			# matched this action+payload but the method is not accepted by the
			# action's policy: the grant is burned (single-use) and refused.
			return False
	if allow_sudo_window and has_management_sudo(user):
		return True
	return False


def _audit_grant(event: str, action: str, user: str, method: str) -> None:
	""" "every issuance/consumption writes an Activity Log row". Routes through
	``notifications._activity_log`` (the audit-row writer) so the trail is a real
	queryable Activity Log entry, and keeps the structured logger breadcrumb (the
	non-blocking-telemetry idiom used across the app). Lazy import keeps this
	every-login-hook module webauthn-free — ``_audit_grant`` is called only
	from the grant mint/consume endpoints, never from a login hook. Non-blocking:
	an audit failure must never break a ceremony."""
	try:
		from passkeys import notifications

		notifications._activity_log(user, f"grant_{event}", f"Passkey grant {event}: {action} ({method})")
	except Exception:
		frappe.log_error(title="passkeys: grant-audit log failed")
	try:
		frappe.logger("passkeys").info(f"passkey grant {event}: action={action} user={user} method={method}")
	except Exception:
		pass


def _grant_token() -> str | None:
	request = getattr(frappe.local, "request", None)
	if request is not None:
		headers = getattr(request, "headers", None)
		if headers is not None:
			token = headers.get(GRANT_HEADER)
			if token:
				return token
	form = getattr(frappe.local, "form_dict", None)
	return form.get(GRANT_KWARG) if form is not None else None


def _raise_confirmation_required(action: str, *, methods: list[str], payload_fingerprint=None) -> None:
	"""Emit the typed-error wire contract: structured keys ride
	``frappe.local.response`` (survive into the JSON error body); clients match
	on ``exc_type`` only."""
	from passkeys.passkey import PasskeyConfirmationRequired

	frappe.local.response["action"] = action
	frappe.local.response["payload_fingerprint"] = payload_fingerprint
	frappe.local.response["methods"] = methods
	raise PasskeyConfirmationRequired(frappe._("Confirm it's you to manage passkeys."))
