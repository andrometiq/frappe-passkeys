# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sudo-window semantics, ending a user's sessions, the impersonation guard and the
action-grant consumer. Folds into ``frappe/passkey.py`` on the core merge.

On the ``on_session_creation`` / ``on_logout`` / ``before_request`` / ``after_request`` hook
chains (every login, logout and request), so it must not import ``webauthn``, directly or
transitively."""

import ast
import hashlib
import inspect
import json
import pickle
import re
import time

import frappe
import redis
from frappe import _
from frappe.utils import cint, now

from passkeys import ceremony, install, state
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

# Ending a user's sessions: rounds before it stops, pauses between marking tries while the cache
# can't be reached, and the cache read chunk.
MAX_SIGN_OUT_ROUNDS = 20
MARKING_PAUSES = (0.1, 0.3)
CACHE_READ_CHUNK = 500

# The form of a session id core issues (frappe.generate_hash).
ISSUED_SESSION_ID = re.compile("[0-9a-f]{56}")


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
	if not ceremony.has_usable_credential(user):
		return
	from passkeys import notifications

	notifications.record_risk_event(
		notifications.RISK_PASSWORD_LOGIN_BY_PASSKEY_HOLDER,
		user,
		f"Password login by passkey holder {user}",
	)


def clear_sudo_window(login_manager=None, **kwargs) -> None:
	"""on_logout: note this session's sid for ``clear_logged_out_sudo_window``. v15/v16 fire
	the hook before choosing between ending this session and another user's, and do not say
	which, so the window is dropped only once the request is done. Never raises."""
	try:
		if install.dormant():
			return
		if frappe.session.sid:
			frappe.local.flags.passkeys_logout_sid = frappe.session.sid
	except Exception:
		frappe.log_error(title="passkeys: sudo-window clear failed")


def clear_logged_out_sudo_window(response=None, request=None) -> None:
	"""after_request: drop the noted session's sudo window only if this request ended that
	session (core swapped in the Guest session), not when it ended another user's. Never raises."""
	try:
		sid = frappe.local.flags.pop("passkeys_logout_sid", None)
		if sid and frappe.session.sid != sid:
			state.clear_sudo_window(sid)
	except Exception:
		frappe.log_error(title="passkeys: sudo-window clear failed")


def end_sessions(user: str, *, keep_current: bool) -> bool:
	"""End ``user``'s sessions for good (all but this request's with ``keep_current``): every
	session of the user, on every device, is marked ended for ``refuse_ended_session``, then ended
	with core's ``delete_session``; later rounds end sessions signed in meanwhile. The sessions are
	ended even when a mark can't be written. Returns False (logged) when a session could not be
	marked or some are left when it stops (a session that fails to end, or the round limit), True
	otherwise. A session that fails to end isn't tried again: each try can take the database's
	whole lock wait. Commits as it goes, and rolls back a failed delete's writes, so call it only
	after the caller's own writes are committed."""
	kept_key = get_stored_session_id(frappe.session.sid) if keep_current else None
	is_complete, previous_keys, skipped_keys = True, None, {kept_key}
	for round_number in range(MAX_SIGN_OUT_ROUNDS):
		listed_keys = _get_session_keys(user, skipped_keys)
		is_complete &= _mark_ended(listed_keys, _get_stored_expiries(listed_keys))
		cached_by_key = {}
		if round_number == 0:  # one cache read per call
			cached_by_key, is_marked = _mark_cached_sessions(user, {kept_key, *listed_keys})
			is_complete &= is_marked
		failed_keys = _delete_sessions(user, listed_keys, cached_by_key)
		is_complete &= not failed_keys
		skipped_keys |= failed_keys
		if not listed_keys or listed_keys == previous_keys:  # none left, or the last round ended none
			return is_complete and not listed_keys
		previous_keys = listed_keys
	if not _get_session_keys(user, skipped_keys):
		return is_complete
	frappe.log_error(title="passkeys: sign-out stopped at its round limit")
	return False


def _get_session_keys(user: str, skipped_keys: set) -> set:
	"""The stored ids of all of ``user``'s sessions but ``skipped_keys``."""
	sessions = frappe.qb.DocType("Sessions")
	stored_keys = frappe.qb.from_(sessions).select(sessions.sid).where(sessions.user == user).run(pluck=True)
	return set(stored_keys) - skipped_keys


def _mark_cached_sessions(user: str, skipped_keys: set) -> tuple[dict[str, dict], bool]:
	"""Mark ``user``'s cached sessions but ``skipped_keys``: (stored id -> session data, whether
	they were marked)."""
	try:
		cached_by_key = _retry(_get_cached_sessions, user, skipped_keys)
	except Exception:
		frappe.log_error(title="passkeys: cached-session read failed", message=frappe.get_traceback())
		return {}, False
	expiries = [data.get("session_expiry") for data in cached_by_key.values()]
	return cached_by_key, _mark_ended(cached_by_key, expiries)


def _mark_ended(stored_keys, expiries: list) -> bool:
	"""Mark each session ended past the longest of ``expiries`` and the site's. False (logged) when
	the marks could not be written."""
	if not stored_keys:
		return True
	try:
		_retry(
			state.mark_sessions_ended, [state.sid_hash(key) for key in stored_keys], _get_mark_ttl(expiries)
		)
	except Exception:
		frappe.log_error(title="passkeys: ended-session mark failed", message=frappe.get_traceback())
		return False
	return True


def _retry(func, *args):
	"""``func(*args)``, tried again after a short pause while the cache can't be reached."""
	for pause in (*MARKING_PAUSES, None):
		try:
			return func(*args)
		except redis.exceptions.ConnectionError:
			if pause is None:
				raise
			time.sleep(pause)


def _delete_sessions(user: str, listed_keys: set, cached_by_key: dict) -> set:
	"""End exactly these sessions: the listed ones with core's ``delete_session`` (by the stored
	id where core takes it); drop the cached copies of the others. Returns the listed ones that
	failed to end: each is logged, its writes and messages dropped, and doesn't stop the others."""
	from frappe.sessions import delete_session

	by_stored_id = "sid_hash" in inspect.signature(delete_session).parameters
	failed_keys = set()
	for key in listed_keys:
		message_count = len(frappe.local.message_log)
		try:
			if by_stored_id:
				delete_session(user=user, reason="Force Logged out by the user", sid_hash=key)
			else:
				delete_session(key, user=user, reason="Force Logged out by the user")
		except Exception:
			frappe.db.rollback()  # a lock wait timeout leaves the delete's earlier writes in
			del frappe.local.message_log[message_count:]
			frappe.log_error(title="passkeys: ending a session failed", message=frappe.get_traceback())
			frappe.db.commit()  # the log stays even if a later delete rolls back
			failed_keys.add(key)
	for key in cached_by_key:
		frappe.cache.hdel("session", key)
	return failed_keys


def _get_cached_sessions(user: str, skipped_keys: set) -> dict[str, dict]:
	"""``user``'s cached sessions but ``skipped_keys``: stored id -> session data. Read in
	chunks; a value that doesn't load is skipped."""
	cached_by_key = {}
	name = frappe.cache.make_key("session")
	for key, value in redis.Redis.hscan_iter(frappe.cache, name, count=CACHE_READ_CHUNK):
		key = frappe.safe_decode(key)
		data = None if key in skipped_keys else _load_cached_session(value)
		if data and data.get("user") == user:
			cached_by_key[key] = data
	return cached_by_key


def _load_cached_session(value: bytes) -> dict | None:
	"""A cached value's session data, the part core resumes the session from (some Frappe versions
	cache it under ``data``)."""
	try:
		value = pickle.loads(value)
	except Exception:
		return None
	data = value.get("data") if isinstance(value, dict) and "data" in value else value
	return data if isinstance(data, dict) else None


def _get_stored_expiries(stored_keys: set) -> list:
	"""Each session's own expiry as its Sessions row stores it; none for a row that doesn't
	parse, and none (logged) when the rows can't be read."""
	if not stored_keys:
		return []
	sessions = frappe.qb.DocType("Sessions")
	try:
		rows = (
			frappe.qb.from_(sessions)
			.select(sessions.sessiondata)
			.where(sessions.sid.isin(list(stored_keys)))
			.run()
		)
	except Exception:
		frappe.log_error(title="passkeys: session expiry read failed", message=frappe.get_traceback())
		return []
	return [_parse_session_data(sessiondata).get("session_expiry") for (sessiondata,) in rows]


def _parse_session_data(text: str | None) -> dict:
	"""A Sessions row's data: JSON from version-16 on, a Python literal before; {} if neither."""
	for parse in (json.loads, ast.literal_eval):
		try:
			data = parse(text or "{}")
		except Exception:
			continue
		return data if isinstance(data, dict) else {}
	return {}


def _get_mark_ttl(expiries: list) -> int:
	"""Past the longest of the site's session expiry and ``expiries``, plus a margin."""
	from frappe.sessions import get_expiry_in_seconds

	seconds = [get_expiry_in_seconds(expiry) for expiry in expiries if _is_expiry(expiry)]
	return max([get_expiry_in_seconds(), *seconds]) + state.ENDED_SESSION_MARGIN


def _is_expiry(value) -> bool:
	return isinstance(value, str) and value.count(":") == 2


def refuse_ended_session() -> None:
	"""before_request: refuse a session this app ended, or a signed-in id not in the form core
	issues (see ``has_issued_form``), with 401 ``SessionExpired``, signing the browser out (session
	and cookies). At most one cache read per signed-in request; none for Guest."""
	if not is_browser_session():
		return
	sid = frappe.session.sid
	stored_key = get_stored_session_id(sid)
	if not has_issued_form(sid):
		drop_cached_session(stored_key)
	elif state.is_session_ended(state.sid_hash(stored_key)):
		from frappe.sessions import delete_session

		delete_session(sid, user=frappe.session.user, reason="Passkey revoked")
	else:
		return
	from frappe.auth import clear_cookies

	clear_cookies()
	# Only ever to Guest: the refused request continues signed out, as after core's logout.
	frappe.set_user("Guest")  # nosemgrep: frappe-setuser
	frappe.local.response["session_expired"] = 1
	raise frappe.SessionExpired


def drop_ended_session(response=None, request=None) -> None:
	"""after_request: if this app ended this request's session, or its id is not in the form core
	issues, drop its cached copy. At most one cache read; none for Guest. Never raises."""
	try:
		session = getattr(frappe.local, "session_obj", None)
		sid = getattr(session, "sid", None)
		callbacks = getattr(getattr(frappe.local, "request", None), "after_response", None)
		if callbacks is None or not sid or "Guest" in (sid, frappe.session.user):
			return
		stored_key, is_checked = get_stored_session_id(sid), has_issued_form(sid)
		# a lambda's repr holds no id
		callbacks.add(lambda: drop_session_if_ended(stored_key, is_checked=is_checked))
	except Exception:
		frappe.log_error(title="passkeys: ended-session check failed")


def drop_session_if_ended(stored_key: str, *, is_checked: bool = True) -> None:
	"""Drop the session's cached copy if this app ended it, or without reading the mark when not
	``is_checked``. Never raises; a failure is logged by its error class only."""
	try:
		if not is_checked or state.is_session_ended(state.sid_hash(stored_key)):
			drop_cached_session(stored_key)
	except Exception as error:
		frappe.logger("passkeys").error(f"ended-session check failed: {type(error).__name__}")


def drop_cached_session(stored_key: str) -> None:
	"""Drop the session's cached copy, as core does when it ends a session."""
	frappe.cache.hdel("session", stored_key)
	frappe.cache.hdel("last_db_session_update", stored_key)


def has_issued_form(sid: str) -> bool:
	"""False when core stores session ids as they are and ``sid`` is not in the form core issues
	them in (56 lowercase hex digits)."""
	return get_stored_session_id(sid) != sid or bool(ISSUED_SESSION_ID.fullmatch(sid))


def get_stored_session_id(sid: str) -> str:
	"""``sid`` as core stores the session (hashed from version-16 on)."""
	from frappe import sessions

	hash_sid = getattr(sessions, "hash_sid", None)
	return hash_sid(sid) if hash_sid else sid


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
			"sid_hash": state.sid_hash(frappe.session.sid),
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
			and record.get("sid_hash") == state.sid_hash(frappe.session.sid)
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
