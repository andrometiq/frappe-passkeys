# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sudo-window semantics, the impersonation guard and the action-grant consumer. Folds
into ``frappe/passkey.py`` on the core merge.

On the ``on_session_creation`` / ``on_logout`` hook chains (every login and logout),
so it must not import ``webauthn``, directly or transitively."""

import hashlib
import json

import frappe
from frappe import _
from frappe.utils import cint, now

from passkeys import install, state
from passkeys.errors import (
	BrowserSessionRequired,
	ImpersonatedSessionRefused,
	PasskeyConfirmationRequired,
)

MANAGE_ACTION = "passkeys.manage"
SET_PASSKEY_ONLY_ACTION = "passkeys.set_passkey_only_login"

# Seeding classes. ``password``/``passkey``/``reauth`` grant a full sudo
# window; ``external`` (email-link / OAuth / social) seeds a window that only the
# restricted first-enrollment bootstrap honours — never general management.
FULL_SUDO_METHODS = ("password", "passkey", "reauth")

GRANT_HEADER = "X-Passkey-Grant"
GRANT_KWARG = "_passkey_grant"


def seed_sudo_window(login_manager=None, **kwargs) -> None:
	"""on_session_creation (after ``make_session``, so the sid exists): seed a sudo window
	classified by login method. A failure here must never take down a login."""
	try:
		if install.dormant():
			return
		user = frappe.session.user
		if not user or user in ("Guest", ""):
			return
		# Core's impersonate lands here inside login_as, before it sets impersonated_by; its
		# "external" window serves only registration, which refuse_impersonated_session refuses.
		method = _classify_login_method()
		set_window(user, method)
		_maybe_record_password_login_risk(user, method, frappe.get_cached_doc("Passkey Settings"))
	except Exception:
		frappe.log_error(title="passkeys: sudo-window seed failed")


def _maybe_record_password_login_risk(user: str, method: str, settings) -> None:
	"""Opt-in (``passkey_notify_password_login``) risk event: a passkey holder signed in
	with their password. Off by default, so the hot login path pays no extra read."""
	if method != "password" or not cint(settings.passkey_notify_password_login):
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
	"""on_logout: drop this session's sudo window. Never raises."""
	try:
		if install.dormant():
			return
		sid = frappe.session.sid
		if sid:
			state.clear_sudo_window(sid)
	except Exception:
		frappe.log_error(title="passkeys: sudo-window clear failed")


def _classify_login_method() -> str:
	"""``passkey`` when the app's own ceremony set ``flags.passkey_login``; ``password``
	for a core username + password login (or the app's own plain-password arm, flagged
	``passkeys_password_login``); ``external`` for anything else — email link, OAuth, social,
	and LDAP (under-granting: it only unlocks the first-enrollment bootstrap)."""
	flags = getattr(frappe.local, "flags", None)
	if flags is not None and flags.get("passkey_login"):
		return "passkey"
	if flags is not None and flags.get("passkeys_password_login"):
		return "password"
	if _is_core_password_login():
		return "password"
	return "external"


def _is_core_password_login() -> bool:
	form = getattr(frappe.local, "form_dict", None)
	cmd = form.get("cmd") if form is not None else None
	# The dispatcher honours a truthy cmd over the path; v15/v16 also log in on cmd=login.
	if cmd:
		return cmd == "login"
	request = getattr(frappe.local, "request", None)
	return request is not None and getattr(request, "path", None) == "/api/method/login"


def is_browser_session(user: str | None = None, sid: str | None = None) -> bool:
	"""True iff ``sid`` is a real cookie session of ``user`` (default: this request's).
	Core's API-key / Basic / OAuth-bearer auth binds the user through ``frappe.set_user``,
	which sets ``sid`` to the user name; a real session's sid is a random hash."""
	user = user or frappe.session.user
	sid = sid or frappe.session.sid
	return bool(user and sid) and sid not in ("Guest", user)


def set_window(user: str, seeded_by: str) -> None:
	"""Seed the sudo window for this session — the single writer, so a window can never
	be keyed on a token-auth sid."""
	if not is_browser_session(user):
		raise BrowserSessionRequired(_("Passkey management requires a signed-in browser session."))
	ttl = cint(frappe.get_cached_doc("Passkey Settings").passkey_reauth_window) or 600
	state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": seeded_by}, ttl)


def get_window(user: str, sid: str | None = None) -> dict | None:
	"""The live sudo window for ``user`` on ``sid``; ``None`` when absent or expired (Redis
	``ex`` is the sole expiry), owned by another user, or ``sid`` is not a browser session."""
	sid = sid or frappe.session.sid
	if not is_browser_session(user, sid):
		return None
	window = state.get_sudo_window(sid)
	if not window or window.get("user") != user:
		return None
	return window


def has_management_sudo(user: str, sid: str | None = None) -> bool:
	"""A full-sudo window is live; an ``external``-seeded one never grants management."""
	window = get_window(user, sid)
	return bool(window and window.get("seeded_by") in FULL_SUDO_METHODS)


def require_authed_user(message: str | None = None) -> str:
	"""The signed-in browser user; ``AuthenticationError`` for Guest and
	``BrowserSessionRequired`` for a token-authenticated request."""
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	if not is_browser_session(user):
		raise BrowserSessionRequired(message or _("Passkey management requires a signed-in browser session."))
	return user


def is_impersonated() -> bool:
	"""True while another user acts as the session user through core's ``impersonate``
	(the Administrator; on v16 also any role granted the User ``impersonate`` permission).
	False outside a session (scheduler, CLI, migrate)."""
	session = getattr(frappe.local, "session", None)
	data = session.get("data") if session else None
	return bool(data and data.get("impersonated_by"))


def refuse_impersonated_session() -> None:
	"""An impersonated session is read-only for passkeys: it never adds, renames or removes
	a passkey, changes a passkey record or setting, confirms as the user, or spends their
	nudge and grace state. Endpoints call it before the rate limit, so a refusal spends no
	counter."""
	if is_impersonated():
		frappe.throw(
			_("Passkeys can't be changed or used while impersonating a user."), ImpersonatedSessionRefused
		)


class ReadOnlyWhileImpersonated:
	"""Controller mixin for the passkey DocTypes: every write verb core runs a controller
	hook for refuses an impersonated session first, whatever the permission flags and
	whoever is impersonated. A controller that defines ``validate`` or ``on_trash`` calls
	``super()`` first."""

	def validate(self):
		refuse_impersonated_session()

	def on_trash(self):
		refuse_impersonated_session()

	def before_rename(self, old, new, merge=False):
		refuse_impersonated_session()

	def after_rename(self, old, new, merge=False):
		# The one hook on every rename, ``validate_rename=False`` included. It runs after the
		# rename SQL and before any commit, so the raise rolls the rename back.
		refuse_impersonated_session()

	def before_discard(self):
		# v16+: ``Document.discard`` sets docstatus 2 directly, with no validate.
		refuse_impersonated_session()


def require_management_sudo(user: str) -> None:
	"""Gate the management surface: without a full-sudo window, raise the 401 contract
	whose confirmation re-seeds the window."""
	if has_management_sudo(user):
		return
	_raise_confirmation_required(MANAGE_ACTION, methods=["passkey", "password", "sudo"])


def canonical_json(payload: dict) -> str:
	"""Pinned server-only canonicalization. JS never computes a hash."""
	return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(params: dict) -> str:
	return hashlib.sha256(canonical_json(params).encode("utf-8")).hexdigest()


def consume_passkey_grant(user: str, action: str, params: dict) -> bool:
	"""The strict gate: only a **passkey-method** grant, never a password grant or a sudo
	window ("the password is not sufficient")."""
	return consume_action_grant(user, action, params, allow_password_fallback=False, allow_sudo_window=False)


def mint_action_grant(user: str, action: str, payload_hash_hex: str, *, method: str) -> str:
	"""Mint a single-use grant bound to ``user + sid + action + payload_hash + method`` and
	return the raw token once; only its SHA-256 is stored, so a cache snapshot never yields
	a usable grant. ``method`` is ``passkey`` or ``password``."""
	token = frappe.generate_hash()
	state.store_grant(
		hashlib.sha256(token.encode("utf-8")).hexdigest(),
		{
			"v": 1,
			"user": user,
			"sid": frappe.session.sid,
			"action": action,
			"payload_hash": payload_hash_hex,
			"method": method,
			"at": now(),
		},
		state.GRANT_TTL,
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
	"""Atomically consume a presented grant bound to user + sid + action + exact payload.
	A ``passkey`` grant always satisfies the gate; a ``password`` grant only with
	``allow_password_fallback``. With no matching grant, ``allow_sudo_window`` accepts a
	live full-sudo window. A matched grant of a refused method is still spent."""
	token = _grant_token()
	if token:
		record = state.consume_grant(hashlib.sha256(token.encode("utf-8")).hexdigest())
		is_match = bool(record) and (
			record.get("user") == user
			and record.get("sid") == frappe.session.sid
			and record.get("action") == action
			and record.get("payload_hash") == payload_hash(params)
		)
		if is_match:
			method = record.get("method")
			if method == "passkey" or (method == "password" and allow_password_fallback):
				_audit_grant("consumed", action, user, method)
				return True
			return False
	return bool(allow_sudo_window and has_management_sudo(user))


def _audit_grant(event: str, action: str, user: str, method: str) -> None:
	"""An Activity Log row plus a ``passkeys`` logger line per grant issue/consume — the
	logger keeps independent evidence if the row insert fails or rolls back. Never raises
	into a ceremony."""
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


def _raise_confirmation_required(
	action: str,
	*,
	methods: list[str],
	payload_fingerprint=None,
	action_label: str | None = None,
	parameter_summary: list[dict] | None = None,
	message: str | None = None,
) -> None:
	"""The typed 401 contract: structured keys ride ``frappe.local.response`` into the
	JSON error body; clients match on ``exc_type``."""
	frappe.local.response["action"] = action
	frappe.local.response["payload_fingerprint"] = payload_fingerprint
	frappe.local.response["methods"] = methods
	if action_label:
		frappe.local.response["action_label"] = action_label
	if parameter_summary:
		frappe.local.response["parameter_summary"] = parameter_summary
	raise PasskeyConfirmationRequired(message or _("Confirm it's you to manage passkeys."))
