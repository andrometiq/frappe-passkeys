# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sudo-window semantics (DESIGN-v1 §7.1) + the passkey-grant consumer (§7.2)
used by the management surface. Folds into ``frappe/passkey.py`` on the core
merge.

**Hook-path import discipline (§1.3):** this module sits on the
``on_session_creation`` / ``on_logout`` hook chains — which fire on *every*
login/logout of *every* user — so it MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe`` and :mod:`passkeys.state`.

Placement note: DESIGN-v1 §1.3 sketches ``seed_sudo_window`` living in
``auth_hooks.py`` (alongside the on_login veto + System Settings 2FA guard,
which land in later phases). Those seams are unbuilt; keeping the sudo seed +
check here in ``session.py`` avoids colliding with that future module and keeps
this hook-path file import-clean. ``hooks.py`` points the hooks here.
"""

import hashlib
import json

import frappe
from frappe.utils import cint, now

from passkeys import state

# Built-in action for the app's own management surface (§7.1 / §7.2).
MANAGE_ACTION = "passkeys.manage"
SET_PASSKEY_ONLY_ACTION = "passkeys.set_passkey_only_login"

# Seeding classes (§7.1). ``password``/``passkey``/``reauth`` grant a full sudo
# window; ``weak`` (email-link / OAuth / social) seeds a window that only the
# restricted first-enrollment bootstrap honours — never general management.
FULL_SUDO_METHODS = ("password", "passkey", "reauth")

GRANT_HEADER = "X-Passkey-Grant"
GRANT_KWARG = "_passkey_grant"


# ---------------------------------------------------------------------------
# on_session_creation seed (§7.1) — fires after make_session inside post_login,
# where the sid already exists (the on_login veto, §9.3, fires BEFORE make_session
# and cannot seed a sid-keyed window).
# ---------------------------------------------------------------------------


def seed_sudo_window(login_manager=None, **kwargs) -> None:
	"""Seed a sudo window for the freshly-created session, classified by login
	method (§7.1). Exception-hardened: a failure here must never take down a
	login (this hook runs on every login of every user)."""
	try:
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
	except Exception:
		frappe.log_error(title="passkeys: sudo-window seed failed")


def clear_sudo_window(login_manager=None, **kwargs) -> None:
	"""on_logout: drop this session's sudo window (§7.5). Exception-hardened."""
	try:
		sid = frappe.session.sid
		if sid:
			state.clear_sudo_window(sid)
	except Exception:
		frappe.log_error(title="passkeys: sudo-window clear failed")


def _classify_login_method() -> str | None:
	"""Best-available classification at ``on_session_creation`` time (§7.1):

	* ``passkey`` — the app's own passwordless / passkey-2FA / uv-setup legs set
	  ``frappe.local.flags.passkey_login`` before ``login_as``.
	* ``password`` — a core username+password login (the ``/api/method/login``
	  endpoint, or the v15/v16 ``cmd=login`` trigger), where a password was
	  verified by ``authenticate``.
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
	if _is_core_password_login():
		return "password"
	return "weak"


def _is_core_password_login() -> bool:
	request = getattr(frappe.local, "request", None)
	if request is not None and getattr(request, "path", None) == "/api/method/login":
		return True
	form = getattr(frappe.local, "form_dict", None)
	# v15/v16 additionally trigger core login on cmd=login (§10 login-trigger row).
	return bool(form is not None and form.get("cmd") == "login")


# ---------------------------------------------------------------------------
# check helpers (§7.1 consumers)
# ---------------------------------------------------------------------------


def get_window(user: str, sid: str | None = None) -> dict | None:
	"""The live sudo window for ``user`` on ``sid`` (Redis ``ex`` is the sole
	expiry authority — an expired window reads back as ``None``, §4.2). Returns
	``None`` when absent or owned by a different user."""
	sid = sid or frappe.session.sid
	window = state.get_sudo_window(sid)
	if not window or window.get("user") != user:
		return None
	return window


def has_management_sudo(user: str, sid: str | None = None) -> bool:
	"""True iff a full-sudo window (password / passkey / reauth-seeded) is live
	for the user (§7.1). A ``weak``-seeded window does NOT satisfy management —
	recovery-grade logins never silently mint management power."""
	window = get_window(user, sid)
	return bool(window and window.get("seeded_by") in FULL_SUDO_METHODS)


def require_management_sudo(user: str) -> None:
	"""Gate the app's management surface (§7.4). Raises the typed
	``PasskeyConfirmationRequired`` retry contract (§3 / §7.2) when no full-sudo
	window is live — the client then runs a passkey confirmation (or password
	re-auth), which re-seeds the window."""
	if has_management_sudo(user):
		return
	_raise_confirmation_required(MANAGE_ACTION, methods=["passkey", "password", "sudo"])


# ---------------------------------------------------------------------------
# passkey-grant consumer (§7.2) — the consumer half of the action-signing
# primitive. The MINTER (confirm.begin_confirmation / verify_confirmation +
# the general @passkey_protected decorator) is Phase 5; only the grant-consuming
# guard needed by set_passkey_only_login (F19, §9.3) is built here.
# ---------------------------------------------------------------------------


def canonical_json(payload: dict) -> str:
	"""Pinned server-only canonicalization (§7.2). JS never computes a hash."""
	return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(params: dict) -> str:
	return hashlib.sha256(canonical_json(params).encode("utf-8")).hexdigest()


def consume_passkey_grant(user: str, action: str, params: dict) -> bool:
	"""Atomically consume a single-use **passkey-method** grant bound to
	user + sid + action + exact payload (§7.2 / §9.3). Returns ``True`` on a
	valid consume, ``False`` otherwise (missing token, wrong owner/sid/action,
	payload mismatch, or a password-minted grant). Never accepts a sudo window
	or a password-minted grant — the F19 threat model ("the password is not
	sufficient")."""
	token = _grant_token()
	if not token:
		return False
	record = state.consume_grant(hashlib.sha256(token.encode("utf-8")).hexdigest())
	if not record:
		return False
	return (
		record.get("user") == user
		and record.get("sid") == frappe.session.sid
		and record.get("action") == action
		and record.get("method") == "passkey"
		and record.get("payload_hash") == payload_hash(params)
	)


def _grant_matches(record: dict, user: str, action: str, params: dict) -> bool:
	"""Ownership/binding predicate shared by both grant consumers: a grant
	authorizes only its exact ``user`` + current sid + declared ``action`` +
	exact payload (§7.2). Method binding is layered by the caller."""
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
	"""Mint a single-use action grant and return the raw token **once** (§7.2).

	The token is stored only as SHA-256 (a cache snapshot never yields a usable
	grant); the record binds ``user + sid + action + payload_hash + method`` and
	expires by Redis ``ex`` alone (default 180 s ≤ the pinned cap). ``method`` is
	``"passkey"`` (a real UV assertion via the confirm ceremony) or ``"password"``
	(a ``reauth_password`` action-grant, accepted only by
	``allow_password_fallback`` actions — never by F19's set_passkey_only_login).
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
	(§7.2). Atomically consumes a presented grant bound to
	user + sid + action + exact payload:

	* a ``passkey``-method grant always satisfies the gate;
	* a ``password``-method grant satisfies it **only** when the action declared
	  ``allow_password_fallback=True`` (the primitive's universal-re-auth mode);
	* when no matching grant token is presented and ``allow_sudo_window=True``, a
	  live full-sudo window (GitHub-sudo ergonomics for the app's own management)
	  satisfies it instead.

	Returns ``True`` on a valid consume, else ``False`` (caller raises the §3 401
	retry contract). Unlike :func:`consume_passkey_grant` (the strict F19 gate),
	this honours the per-action fallback policy — but the F19 invariant still
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
			# action's policy (F19): the grant is burned (single-use) and refused.
			return False
	if allow_sudo_window and has_management_sudo(user):
		return True
	return False


def _audit_grant(event: str, action: str, user: str, method: str) -> None:
	"""§7.2 "every issuance/consumption writes an Activity Log row". The Activity
	Log DocType rows are owned by ``notifications.py`` (a later phase, per the same
	deferral noted in ``api/credentials.py``); until then this is a structured
	logger line so the audit trail is never silently dropped. Non-blocking."""
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
	"""Emit the §3 typed-error wire contract: structured keys ride
	``frappe.local.response`` (survive into the JSON error body); clients match
	on ``exc_type`` only."""
	from passkeys.passkey import PasskeyConfirmationRequired

	frappe.local.response["action"] = action
	frappe.local.response["payload_fingerprint"] = payload_fingerprint
	frappe.local.response["methods"] = methods
	raise PasskeyConfirmationRequired(frappe._("Confirm it's you to manage passkeys."))
