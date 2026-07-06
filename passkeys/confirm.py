# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Action-confirmation / "passkey signing" primitive (DESIGN-v1 §7.2 / J6).

This is the **public API surface** other Frappe apps use to require a fresh
passkey confirmation before a sensitive whitelisted action — the
"approve any other action with a passkey" primitive:

    from passkeys.confirm import passkey_protected

    @frappe.whitelist(methods=["POST"])
    @passkey_protected(action="myapp.release_payment", bind_params=["payment_id"],
                       allow_password_fallback=True, allow_sudo_window=False)
    def release_payment(payment_id):
        ...

The decorator requires a single-use grant bound to *(this action, this session,
this exact payload)* before the wrapped function runs; absent/invalid, it raises
``PasskeyConfirmationRequired`` (HTTP 401) carrying a server-computed
``payload_fingerprint`` the client echoes back. The client half
(``frappe.passkeys.confirm`` / ``frappe.passkeys.call`` + dialog) is the frozen
JS bundle (``public/js/passkey_confirm.js``); this module answers the three
whitelisted method paths that bundle pins:

* ``passkeys.confirm.begin_confirmation`` — mint the assertion options + ceremony.
* ``passkeys.confirm.verify_confirmation`` — verify the UV assertion, mint the grant.
* ``passkeys.confirm.reauth_password``    — password fallback: seed the sudo window
  (no action) OR mint a password-method action grant (``allow_password_fallback``).

``webauthn`` (via ``passkeys.engine``) is imported **lazily inside the ceremony
bodies** (§1.3 hook-path import discipline); the decorator + ``session``/``state``
imports are webauthn-free, so an app can decorate a method at module import time
without pulling the crypto wheel onto its import path.

Folds into ``frappe/passkey.py`` on the core merge (``frappe.passkey`` server
namespace, ``frappe.ui.passkey`` JS namespace)."""

import functools
import inspect
from dataclasses import dataclass, field

import frappe
from frappe import _
from frappe.utils import cint, now_datetime

from passkeys import policy, session, state

# ---------------------------------------------------------------------------
# Per-action policy registry (§7.2). The @passkey_protected decorator declares
# an action's fallback policy at import time; the minter endpoints consult the
# registry so `begin_confirmation`'s `methods` and `reauth_password`'s
# action-grant path honour the SAME policy the consumer enforces. The registry
# is a UX/correctness aid — the security boundary is always the consumer
# (session.consume_action_grant / consume_passkey_grant), which re-derives the
# payload hash from real kwargs and enforces method binding regardless of what
# the registry says (a cross-worker import gap can only under-offer a method,
# never authorize one).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionPolicy:
	"""The confirmation policy for one action (mirrors the decorator kwargs)."""

	action: str
	bind_params: tuple = field(default_factory=tuple)
	allow_password_fallback: bool = True
	allow_sudo_window: bool = False


_ACTION_POLICIES: dict[str, ActionPolicy] = {}


def register_action(policy_: ActionPolicy) -> None:
	"""Record an action's policy (idempotent; last decorator wins on reload)."""
	_ACTION_POLICIES[policy_.action] = policy_


def get_action_policy(action: str) -> ActionPolicy:
	"""The registered policy for ``action``, or a safe default. The default
	mirrors the decorator defaults (``allow_password_fallback=True``,
	``allow_sudo_window=False``) so an app using only the imperative
	:func:`require_passkey_confirmation` (no import-time decorator) still gets the
	universal-re-auth behaviour. Actions that must never accept a password (F19)
	are pre-registered below, so the default can never weaken them."""
	return _ACTION_POLICIES.get(action) or ActionPolicy(action=action)


# Built-in actions the app's own surfaces confirm (§7.1 / §7.4 / §9.3). Registered
# eagerly (this module is import-clean) so the minter serves them with the right
# `methods` even when the consuming endpoint module hasn't been imported yet.
register_action(
	ActionPolicy(
		action=session.MANAGE_ACTION,  # "passkeys.manage" — management surface (§7.4)
		bind_params=(),
		allow_password_fallback=True,  # first-enrollment / passkey-less users
		allow_sudo_window=True,  # GitHub-sudo ergonomics for management
	)
)
register_action(
	ActionPolicy(
		action=session.SET_PASSKEY_ONLY_ACTION,  # "passkeys.set_passkey_only_login" (§9.3 / F19)
		bind_params=("enabled",),
		allow_password_fallback=False,  # a password must never disable "password-not-sufficient"
		allow_sudo_window=False,
	)
)


# ===========================================================================
# Public API — the decorator + imperative guards other apps import
# ===========================================================================


def passkey_protected(
	action: str,
	*,
	bind_params: list | tuple | None = None,
	allow_password_fallback: bool = True,
	allow_sudo_window: bool = False,
):
	"""Require a fresh passkey confirmation before a whitelisted method runs (§7.2).

	Put this **below** ``@frappe.whitelist`` on any sensitive server method::

	    @frappe.whitelist(methods=["POST"])
	    @passkey_protected(action="myapp.release_payment", bind_params=["payment_id"])
	    def release_payment(payment_id): ...

	Parameters
	----------
	action:
	    A stable, globally-unique action id (namespace it with your app, e.g.
	    ``"myapp.release_payment"``). The grant, the ceremony, and the client
	    dialog all key on this string.
	bind_params:
	    The subset of the method's arguments the confirmation commits to. The
	    grant is bound to ``sha256(canonical_json({k: value for k in bind_params}))``
	    — a grant minted for ``payment_id="PAY-1"`` cannot authorize ``"PAY-2"``.
	    Omit for actions with no payload (the empty payload still binds action +
	    session).
	allow_password_fallback:
	    ``True`` (default) — the primitive is a universal re-auth API; a user with
	    no passkey may satisfy the gate by re-entering their password (the dialog
	    upsells passkey creation). ``False`` — passkey-only assurance: a
	    password-minted grant is refused for this action.
	allow_sudo_window:
	    ``True`` — a live full-sudo window (a fresh interactive login or a prior
	    confirmation) satisfies the gate without a new gesture (GitHub-sudo
	    ergonomics; the app's own ``passkeys.manage`` uses this). Default ``False``
	    — every call needs its own gesture.

	On a missing/invalid grant it raises :class:`PasskeyConfirmationRequired`
	(HTTP 401) with ``{action, payload_fingerprint, methods}`` on the JSON body;
	the ``frappe.passkeys.call`` client catches it, runs the confirmation dialog,
	and retries once with the ``X-Passkey-Grant`` header. The grant is consumed
	**before** the wrapped function runs — a failed action burns the gesture
	(A-F20: one gesture = one action attempt)."""
	policy_ = ActionPolicy(
		action=action,
		bind_params=tuple(bind_params or ()),
		allow_password_fallback=bool(allow_password_fallback),
		allow_sudo_window=bool(allow_sudo_window),
	)
	register_action(policy_)

	def decorator(fn):
		@functools.wraps(fn)
		def wrapper(*args, **kwargs):
			params = _bound_params(fn, args, kwargs, policy_.bind_params)
			_consume_or_raise(policy_, params)
			return fn(*args, **kwargs)

		return wrapper

	return decorator


def require_passkey_confirmation(
	action: str,
	params: dict | None = None,
	*,
	allow_password_fallback: bool = True,
	allow_sudo_window: bool = False,
) -> None:
	"""Imperative form of :func:`passkey_protected`, for dynamic call sites where
	the action or payload is only known at runtime::

	    require_passkey_confirmation("myapp.release_payment", {"payment_id": pid})

	Consumes a matching grant (or a permitted fallback) and returns; otherwise
	raises the §3 401 retry contract. Registers/updates the action policy so the
	minter offers the same ``methods``."""
	params = dict(params or {})
	policy_ = _ACTION_POLICIES.get(action) or ActionPolicy(
		action=action,
		bind_params=tuple(params.keys()),
		allow_password_fallback=bool(allow_password_fallback),
		allow_sudo_window=bool(allow_sudo_window),
	)
	register_action(policy_)
	_consume_or_raise(policy_, params)


def has_valid_grant(
	action: str,
	params: dict | None = None,
	*,
	allow_password_fallback: bool = True,
	allow_sudo_window: bool = False,
) -> bool:
	"""Non-raising predicate: ``True`` iff a grant (or permitted fallback) for
	``(action, params)`` is present for the current session. **Consumes** the
	grant on a hit — grants are single-use, so "check" and "spend" are the same
	atomic operation; call this exactly once at the point you act. Prefer the
	decorator or :func:`require_passkey_confirmation` unless you need to branch on
	the outcome yourself."""
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		return False
	return session.consume_action_grant(
		user,
		action,
		dict(params or {}),
		allow_password_fallback=bool(allow_password_fallback),
		allow_sudo_window=bool(allow_sudo_window),
	)


def _consume_or_raise(policy_: ActionPolicy, params: dict) -> None:
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	if session.consume_action_grant(
		user,
		policy_.action,
		params,
		allow_password_fallback=policy_.allow_password_fallback,
		allow_sudo_window=policy_.allow_sudo_window,
	):
		return
	_raise_confirmation_required(policy_.action, params, policy_)


def _bound_params(fn, args, kwargs, bind_params) -> dict:
	"""Extract the declared ``bind_params`` from the call, robust to positional
	or keyword passing (frappe delivers whitelisted args as kwargs, but bind the
	signature so ``bind_params`` is order-independent)."""
	if not bind_params:
		return {}
	try:
		bound = inspect.signature(fn).bind_partial(*args, **kwargs)
		bound.apply_defaults()
		source = bound.arguments
	except TypeError:
		source = kwargs
	return {k: source.get(k) for k in bind_params}


def _raise_confirmation_required(action: str, params: dict, policy_: ActionPolicy) -> None:
	"""Emit the §3 401 retry contract with a SERVER-computed payload fingerprint
	(A36) the client echoes back verbatim on the confirmation round-trip."""
	fingerprint = session.payload_hash(params)
	methods = _confirm_methods(frappe.session.user, policy_)
	session._raise_confirmation_required(action, methods=methods, payload_fingerprint=fingerprint)


def _confirm_methods(user: str, policy_: ActionPolicy) -> list:
	"""Authoritative per-user subset of ``["passkey", "password", "sudo"]`` the
	dialog may offer for this action (§7.2 begin-response ``methods``)."""
	methods = []
	if _enabled_credentials(user):
		methods.append("passkey")
	if policy_.allow_password_fallback:
		methods.append("password")
	if policy_.allow_sudo_window:
		methods.append("sudo")
	return methods


# ===========================================================================
# Whitelisted ceremony endpoints (client contract: passkeys.confirm.*)
# ===========================================================================


@frappe.whitelist(methods=["POST"])
def begin_confirmation(action: str, params=None, payload_hash=None):
	"""Mint UV-required assertion options + a ``confirm`` ceremony for ``action``
	(§7.2). The client sends EITHER ``params`` (raw bound params — the server
	computes the payload hash, A36) OR ``payload_hash`` (the verbatim
	``payload_fingerprint`` echoed from a prior 401); they are mutually exclusive
	and **no hash is ever computed client-side**.

	Returns ``{state_id, options, payload_fingerprint, methods}`` — ``options``
	requests ``userVerification: "required"`` (§7.2); ``methods`` is the
	authoritative per-user subset of ``["passkey","password","sudo"]``. Raises
	417 ``PasskeyServedByCore`` when core serves passkeys natively (§11)."""
	_refuse_if_core_native()
	user = _require_user()
	state.rate_limit_user("begin_confirmation", 30, 300)  # §3.0 row 14: 30/5 min/user
	action = _require_action(action)
	fingerprint = _resolve_payload_hash(params, payload_hash)

	from passkeys import engine

	settings = frappe.get_cached_doc("Passkey Settings")
	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		raise frappe.AuthenticationError(_("Passkeys are not available on this host."))
	origins = policy.resolve_origins(settings, rp_id)
	_enforce_request_host(origins)

	creds = _enabled_credentials(user)
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id,
		allow_credentials=[
			{"id": row.credential_id, "transports": _transports(row.transports)} for row in creds
		],
		user_verification=policy.UV_WIRE["confirmation"],  # "required" (§3.7 / §7.2)
		# A59 (§7.2): pin the browser wire timeout to THIS ceremony's server-side TTL
		# (state.CONFIRM_CEREMONY_TTL = 180 s), not the engine's 300 s default. The
		# login/registration ceremonies inherit the 300 s default because their
		# store_ceremony TTL is the matching 300 s CEREMONY_TTL; the confirm ceremony's
		# TTL is shorter, so a defaulted 300 s wire timeout would let a slow hybrid
		# cross-device confirmation (3-5 min) clear the browser gesture only to fail
		# server-side on the already-expired ceremony. Derive it from the TTL constant
		# so the two can never drift apart.
		timeout_ms=state.CONFIRM_CEREMONY_TTL * 1000,
	)
	state_id = state.store_ceremony(
		{
			"v": 1,
			"type": "confirm",
			"user": user,
			"sid": frappe.session.sid,
			"action": action,
			"payload_hash": fingerprint,
			"challenge_b64": challenge_b64,
			"rp_id": rp_id,
			"origins": origins,
			"allow_sha256": [row.credential_id_sha256 for row in creds],
			"created_at": now_datetime().isoformat(),
		},
		ttl=state.CONFIRM_CEREMONY_TTL,
	)
	return {
		"state_id": state_id,
		"options": options,
		"payload_fingerprint": fingerprint,
		"methods": _confirm_methods(user, get_action_policy(action)),
	}


@frappe.whitelist(methods=["POST"])
def verify_confirmation(state_id: str, credential):
	"""Verify the confirmation assertion and mint a single-use grant (§7.2).

	§3.1 ladder + sid binding + **UV bit must be 1** (a UV-less completion is a
	server-side dead end — confirmation always requires verification) + the §3.7
	``uv_initialized`` gate (flip iff a password-seeded sudo window accompanies
	this session; otherwise route to the password tab). On success returns
	``{grant: "<token>"}`` — the single-use, 180 s, user+sid+action+payload
	bound, ``passkey``-method grant. Any failure raises the uniform typed error;
	the client never re-POSTs an assertion (A35)."""
	_refuse_if_core_native()
	user = _require_user()
	state.rate_limit_user("verify_confirmation", 30, 300)  # §3.0 row 15: 30/5 min/user

	from passkeys import engine

	credential = _as_dict(credential)

	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "confirm":
		raise _ceremony_expired()
	# sid + user binding: a ceremony minted for another session/user is unusable.
	if record.get("user") != user or record.get("sid") != frappe.session.sid:
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	settings = frappe.get_cached_doc("Passkey Settings")
	_enforce_request_host(record.get("origins") or [])

	# resolve the asserted credential: must belong to the user AND be a member of
	# THIS ceremony's allow-list (the StrongKey credential-substitution defence).
	cred = _resolve_ceremony_credential(record, credential, user)

	result = engine.verify_authentication(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		credential_public_key=cred.public_key,
		stored_sign_count=cint(cred.sign_count),
		stored_backup_eligible=bool(cint(cred.backup_eligible)),
		require_user_verification=False,  # UV enforced app-side below (§3.7 / §7.2)
		sign_count_hard_fail=bool(cint(settings.passkey_sign_count_hard_fail)),
	)
	# UV bit MUST be 1 for a confirmation (§7.2) — a wire-`preferred` downgrade or
	# a non-UV authenticator cannot mint an action grant.
	if not result.user_verified:
		raise frappe.AuthenticationError(_("Please verify it's you to confirm this action."))
	# §3.7 uvInitialized gate (L3 §4): while `uv_initialized` is false the UV bit
	# MUST NOT be relied upon as a verification factor. The false→true flip is
	# allowed iff a password accompanied this session (a password/reauth-seeded
	# sudo window); otherwise the typed error routes the dialog to its password
	# tab (§7.2) — possession alone never mints a confirmation grant.
	uv_flip_pending = not cint(cred.uv_initialized)
	if uv_flip_pending:
		window = session.get_window(user)
		if not (window and window.get("seeded_by") in ("password", "reauth")):
			session._raise_confirmation_required(
				record["action"], methods=["password"], payload_fingerprint=record["payload_hash"]
			)

	# sign-count policy applies (upward-only store + flag/hard-fail; §3.6).
	_advance_credential(cred.name, result)
	if uv_flip_pending:
		# the standard password-accompanied uv_initialized flip (§3.7 — the same
		# idiom as the verified second-factor leg in passkey.py).
		frappe.db.set_value("WebAuthn Credential", cred.name, "uv_initialized", 1, update_modified=False)

	token = session.mint_action_grant(user, record["action"], record["payload_hash"], method="passkey")
	# §7.1: a completed passkey confirmation for the built-in ``passkeys.manage``
	# action ALSO seeds the full-sudo window — the sudo-gated management endpoints
	# (``delete_credential`` / explicit ``begin_registration``) check that window,
	# not the grant, so without this the client's confirm→retry dance re-fails the
	# window check (build-p6-frontend-manifest.md §5). Scoped strictly to
	# ``passkeys.manage``: a third-party action confirmation never mints a
	# management sudo window (that would be a privilege leak).
	if record.get("action") == session.MANAGE_ACTION:
		_seed_management_window(user, "passkey")
	return {"grant": token}


@frappe.whitelist(methods=["POST"])
def reauth_password(pwd: str, action=None, payload_fingerprint=None):
	"""Password fallback (§7.2 / §3.0 row 16). Two modes on one endpoint:

	* **No ``action``** — seed the full-sudo window for the app's own management
	  surface (§7.1), so passkey-less users and first-enrollment stay usable.
	* **With ``action`` (+ ``payload_fingerprint``)** — mint a ``password``-method
	  action grant bound to ``(user, sid, action, payload_hash)``, **but only when
	  that action declared ``allow_password_fallback=True``**. An action that
	  requires passkey-grade assurance (F19's set_passkey_only_login) refuses here,
	  and even if it did not, its consumer rejects any non-passkey method.

	``check_password`` + a per-user failure tracker + the app throttle guard the
	password oracle (§3 preamble, A23/A49). Raises 417 when core is native (§11).

	.. note::
	   The frozen spec (§7.2) pins ``reauth_password`` as *"reaches only the sudo
	   window"* yet also requires an ``allow_password_fallback`` action-grant with a
	   ``password``-method grant whose minting endpoint it never names. Rather than
	   invent a new whitelist name, this endpoint's params are **extended**
	   (``{pwd, action?, payload_fingerprint?}``): the bare-``pwd`` sudo-seed case is
	   unchanged; ``action`` present adds the action-grant path. See
	   ``local-notes/build-p5-server-notes.md`` improvisation 1."""
	from frappe.utils.password import check_password

	_refuse_if_core_native()
	user = _require_user()
	state.rate_limit_user("reauth_password", 5, 300)  # §3.0 row 16: 5/5 min/user

	# §7.4 / §9.4 row 7: under site `disable_user_pass_login`, a password can no
	# longer re-auth for management once the user holds ≥1 passkey — only the
	# passkey grant counts. Refuse before touching the password oracle at all.
	if frappe.get_system_settings("disable_user_pass_login") and _has_enabled_passkey(user):
		raise frappe.AuthenticationError(
			_("Use your passkey to confirm — password re-authentication is disabled for this account.")
		)

	# app-owned per-user password-oracle throttle (§3.0 / A49).
	if state.is_password_throttled(user):
		raise frappe.AuthenticationError(_("Too many attempts. Please try again later."))
	try:
		check_password(user, pwd)
	except frappe.AuthenticationError:
		state.record_password_failure(user)
		raise frappe.AuthenticationError(_("Incorrect password."))
	state.clear_password_failures(user)

	if action:
		action = _require_action(action)
		policy_ = get_action_policy(action)
		if not policy_.allow_password_fallback:
			# passkey-only assurance action — no password grant is ever minted (F19).
			raise frappe.AuthenticationError(
				_("This action requires a passkey — a password can't confirm it.")
			)
		if not payload_fingerprint:
			frappe.throw(_("Missing confirmation payload."), frappe.ValidationError)
		token = session.mint_action_grant(user, action, str(payload_fingerprint), method="password")
		# §7.1: the password door for ``passkeys.manage`` seeds the full-sudo window
		# too (same as the passkey door in ``verify_confirmation``), so the sudo-gated
		# management endpoints pass on retry. Reachable only when this user may still
		# password-re-auth for management — the §7.4/§9.4-row-7 refusal above already
		# blocks a passkey holder under ``disable_user_pass_login``.
		if action == session.MANAGE_ACTION:
			_seed_management_window(user, "reauth")
		return {"grant": token}

	# bare sudo seed (§7.1): a full-sudo window seeded by a fresh password re-auth.
	settings = frappe.get_cached_doc("Passkey Settings")
	ttl = cint(settings.passkey_reauth_window) or 600
	state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "reauth"}, ttl)
	return {"seeded": True}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _seed_management_window(user: str, seeded_by: str) -> None:
	"""Seed the full-sudo window a completed ``passkeys.manage`` confirmation grants
	(§7.1) — the window the sudo-gated management endpoints (``delete_credential`` /
	explicit ``begin_registration``) check. ``seeded_by`` is ``passkey`` (a UV
	assertion) or ``reauth`` (the password door); both are §7.1 full-sudo classes,
	and both mirror the fresh-login / bare-``reauth_password`` seed shape + TTL."""
	settings = frappe.get_cached_doc("Passkey Settings")
	ttl = cint(settings.passkey_reauth_window) or 600
	state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": seeded_by}, ttl)


def _resolve_payload_hash(params, payload_hash) -> str:
	"""Server authority over the payload hash (A36). ``params`` ⇒ compute the hash
	with the pinned Python canonicalization; ``payload_hash`` ⇒ the verbatim echoed
	fingerprint (a client lying here only mints a grant the consumer's own
	recomputation rejects — a correctness contract, not a security one). Mutually
	exclusive: a client supplying both is rejected outright."""
	if params is not None and payload_hash is not None:
		frappe.throw(_("Send either params or a payload fingerprint, not both."), frappe.ValidationError)
	if payload_hash is not None:
		return str(payload_hash)
	return session.payload_hash(_as_dict(params) or {})


def _resolve_ceremony_credential(record, credential, user):
	import hashlib

	cred_id = credential.get("id") or credential.get("rawId")
	if not cred_id:
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	sha = hashlib.sha256(_b64url_decode(cred_id)).hexdigest()
	if sha not in set(record.get("allow_sha256") or []):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	cred = frappe.db.get_value(
		"WebAuthn Credential",
		{"credential_id_sha256": sha},
		["name", "user", "enabled", "public_key", "sign_count", "backup_eligible", "uv_initialized"],
		as_dict=True,
	)
	if not cred or cred.user != user or not cint(cred.enabled):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	return cred


def _enabled_credentials(user: str) -> list:
	"""The user's enabled credentials (id + sha + transports) — the confirmation
	ceremony's ``allowCredentials`` and the ``passkey``-method availability signal."""
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user, "enabled": 1},
		fields=["credential_id", "credential_id_sha256", "transports"],
	)


def _has_enabled_passkey(user: str) -> bool:
	"""True iff the user holds ≥1 enabled credential (§7.4 / §9.4 row 7)."""
	return bool(frappe.db.exists("WebAuthn Credential", {"user": user, "enabled": 1}))


def _refuse_if_core_native() -> None:
	"""Dormant-shell contract (§11): delegate to the canonical guard so the confirm
	surface raises the SAME typed 417 (and rides the same one-time advisory) as
	every other app endpoint — no duplicated switch logic (§11)."""
	from passkeys.passkey import refuse_if_core_native

	refuse_if_core_native()


def _require_user() -> str:
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	return user


def _require_action(action) -> str:
	action = (action or "").strip() if isinstance(action, str) else action
	if not action or not isinstance(action, str):
		frappe.throw(_("A confirmation action is required."), frappe.ValidationError)
	return action


def _ceremony_expired():
	from passkeys.passkey import CeremonyExpired

	return CeremonyExpired(_("That took too long — please try again."))


def _advance_credential(name, result) -> None:
	from passkeys.passkey import _advance_credential as advance

	advance(name, result)


def _enforce_request_host(origins) -> None:
	from passkeys.passkey import _enforce_request_host as enforce

	enforce(origins or [])


def _b64url_decode(value: str) -> bytes:
	from passkeys.passkey import _b64url_decode as decode

	return decode(value)


def _transports(raw) -> list:
	import json

	try:
		return json.loads(raw or "[]")
	except (TypeError, ValueError):
		return []


def _as_dict(value):
	import json

	if value is None:
		return None
	return json.loads(value) if isinstance(value, str) else value
