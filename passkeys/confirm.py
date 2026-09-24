# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Action confirmation — the **public API** other apps use to require a fresh passkey
before a sensitive whitelisted action (``@passkey_protected``), plus the three method
paths the client bundle pins: ``begin_confirmation``, ``verify_confirmation`` and
``reauth_password``. Folds into ``frappe/passkey.py`` on the core merge.

``webauthn`` is imported lazily inside the ceremony bodies, so an app can decorate a
method at import time without pulling the crypto wheel onto its import path."""

import functools
import hashlib
import inspect
import json
from dataclasses import dataclass, field

import frappe
from frappe import _
from frappe.utils import cint, now_datetime

from passkeys import ceremony, policy, session, state
from passkeys.errors import CeremonyExpired, CeremonyFailed, refuse_if_core_native

# Per-action policy registry. A protected call also publishes its policy to the shared
# cache before the 401, so the begin/reauth round-trip can land on another worker. The
# security boundary stays the consumer, which re-derives the payload hash from the real
# call and enforces the method binding.


@dataclass(frozen=True)
class ActionPolicy:
	"""The confirmation policy for one action (mirrors the decorator kwargs)."""

	action: str
	bind_params: tuple = field(default_factory=tuple)
	allow_password_fallback: bool = False
	allow_sudo_window: bool = False
	display_label: str | None = None
	display_params: tuple = field(default_factory=tuple)


_ACTION_POLICIES: dict[str, ActionPolicy] = {}
_ACTION_POLICY_PREFIX = "passkeys:action-policy:"
_ACTION_POLICY_TTL = 24 * 60 * 60


def register_action(policy_: ActionPolicy) -> None:
	"""Record an action's policy (idempotent; last decorator wins on reload)."""
	_ACTION_POLICIES[policy_.action] = policy_


def get_action_policy(action: str) -> ActionPolicy:
	"""Return a local or shared policy, failing closed for an unknown action."""
	return (
		_ACTION_POLICIES.get(action)
		or _read_shared_action_policy(action)
		or ActionPolicy(action=action, allow_password_fallback=False)
	)


def _action_policy_key(action: str) -> str:
	return _ACTION_POLICY_PREFIX + hashlib.sha256(action.encode()).hexdigest()


def _publish_action_policy(policy_: ActionPolicy) -> None:
	"""Best-effort cross-worker publication for the immediate retry round-trip."""
	payload = {
		"v": 1,
		"action": policy_.action,
		"bind_params": list(policy_.bind_params),
		"allow_password_fallback": policy_.allow_password_fallback,
		"allow_sudo_window": policy_.allow_sudo_window,
		"display_label": policy_.display_label,
		"display_params": [list(item) for item in policy_.display_params],
	}
	try:
		frappe.cache.set(  # nosemgrep: frappe-cache-breaks-multitenancy
			frappe.cache.make_key(_action_policy_key(policy_.action)),
			json.dumps(payload),
			ex=_ACTION_POLICY_TTL,
		)
	except Exception:
		frappe.log_error(title="passkeys: action policy cache publication failed")


def _read_shared_action_policy(action: str) -> ActionPolicy | None:
	try:
		# nosemgrep: frappe-cache-breaks-multitenancy
		raw = frappe.cache.get(frappe.cache.make_key(_action_policy_key(action)))
		data = json.loads(raw) if raw is not None else None
		if not isinstance(data, dict) or data.get("v") != 1 or data.get("action") != action:
			return None
		bind_params = data.get("bind_params")
		display_params = data.get("display_params")
		if not isinstance(bind_params, list) or not isinstance(display_params, list):
			return None
		if not all(isinstance(name, str) for name in bind_params):
			return None
		if not all(
			isinstance(item, list)
			and len(item) == 2
			and isinstance(item[0], str)
			and isinstance(item[1], str)
			for item in display_params
		):
			return None
		label = data.get("display_label")
		if label is not None and not isinstance(label, str):
			return None
		return ActionPolicy(
			action=action,
			bind_params=tuple(bind_params),
			allow_password_fallback=data.get("allow_password_fallback") is True,
			allow_sudo_window=data.get("allow_sudo_window") is True,
			display_label=label,
			display_params=tuple(tuple(item) for item in display_params),
		)
	except Exception:
		return None


# Built-in actions, registered eagerly so the minter serves them before the consuming
# endpoint module is imported.
register_action(
	ActionPolicy(
		action=session.MANAGE_ACTION,  # "passkeys.manage" — management surface
		bind_params=(),
		allow_password_fallback=True,  # first-enrollment / passkey-less users
		allow_sudo_window=True,
		display_label="Manage passkeys",
	)
)
register_action(
	ActionPolicy(
		action=session.SET_PASSKEY_ONLY_ACTION,  # "passkeys.set_passkey_only_login"
		bind_params=("enabled",),
		allow_password_fallback=False,  # a password must never disable "password-not-sufficient"
		allow_sudo_window=False,
		display_label="Change passkey-only login",
		display_params=(("enabled", "Passkey-only login"),),
	)
)


def passkey_protected(
	action: str,
	*,
	bind_params: list | tuple | None = None,
	allow_password_fallback: bool = False,
	allow_sudo_window: bool = False,
	display_label: str | None = None,
	display_params: dict[str, str] | None = None,
):
	"""Require a fresh passkey confirmation before a whitelisted method runs. Put it
	**below** ``@frappe.whitelist``::

	    @frappe.whitelist(methods=["POST"])
	    @passkey_protected(action="myapp.release_payment", bind_params=["payment_id"])
	    def release_payment(payment_id): ...

	* ``action`` — a stable, app-namespaced id; the grant, ceremony and dialog key on it.
	* ``bind_params`` — the arguments the grant commits to (``sha256`` of their canonical
	  JSON, docs/security.md): a grant for ``payment_id="PAY-1"`` cannot authorize
	  ``"PAY-2"``. Omitted, the grant still binds action + session.
	* ``allow_password_fallback`` — opt in to accepting a password-minted grant, so a
	  user without a passkey can confirm with their password.
	* ``allow_sudo_window`` — a live full-sudo window satisfies the gate without a new
	  gesture.
	* ``display_label`` / ``display_params`` — translated dialog metadata; only the bound
	  parameters named in ``display_params`` are ever shown to the client.

	Without a valid grant it raises :class:`PasskeyConfirmationRequired` (401) with
	``{action, payload_fingerprint, methods}``; ``frappe.passkeys.call`` runs the dialog
	and retries once with the ``X-Passkey-Grant`` header. The grant is consumed before the
	wrapped function runs, so a failed action still spends the gesture."""
	bound_names = tuple(bind_params or ())
	display_items = tuple((display_params or {}).items())
	if any(name not in bound_names for name, _label in display_items):
		raise ValueError("display_params must be a subset of bind_params")
	policy_ = ActionPolicy(
		action=action,
		bind_params=bound_names,
		allow_password_fallback=bool(allow_password_fallback),
		allow_sudo_window=bool(allow_sudo_window),
		display_label=display_label,
		display_params=display_items,
	)
	register_action(policy_)

	def decorator(fn):
		parameters = inspect.signature(fn).parameters
		if not any(parameter.kind is parameter.VAR_KEYWORD for parameter in parameters.values()):
			unknown = [name for name in bound_names if name not in parameters]
			if unknown:
				raise ValueError(f"bind_params not in the signature of {fn.__qualname__}: {unknown}")

		@functools.wraps(fn)
		def wrapper(*args, **kwargs):
			params = _bound_params(fn, args, kwargs, policy_)
			_publish_action_policy(policy_)
			user = session.require_authed_user()
			if not session.consume_action_grant(
				user,
				policy_.action,
				params,
				allow_password_fallback=policy_.allow_password_fallback,
				allow_sudo_window=policy_.allow_sudo_window,
			):
				_raise_confirmation_required(policy_, params)
			return fn(*args, **kwargs)

		return wrapper

	return decorator


def _bound_params(fn, args, kwargs, policy_: ActionPolicy) -> dict:
	"""Bind the whole call to ``fn``'s signature and return the payload the grant
	commits to; rule in docs/security.md ("Action-confirmation grants"). A call
	that does not bind, or a bound name that could mean two values, is refused
	before any grant is looked up."""
	signature = inspect.signature(fn)
	parameters = signature.parameters
	var_keyword = next((p.name for p in parameters.values() if p.kind is p.VAR_KEYWORD), None)
	# Before Python 3.14 ``bind`` rejects a keyword named like a positional-only
	# parameter although ``**kwargs`` absorbs it at call time; route it there by hand.
	routed = {
		name: value
		for name, value in kwargs.items()
		if var_keyword and name in parameters and parameters[name].kind is inspect.Parameter.POSITIONAL_ONLY
	}
	try:
		bound = signature.bind(*args, **{name: value for name, value in kwargs.items() if name not in routed})
	except TypeError:
		_refuse_unbindable_call(policy_.action)
	bound.apply_defaults()
	arguments = bound.arguments
	extra = {**arguments.get(var_keyword, {}), **routed}
	if var_keyword:
		arguments[var_keyword] = extra
	payload = {}
	for name in policy_.bind_params:
		if name in parameters:
			if name in extra:  # positional-only, *args or **kwargs name also passed as a keyword
				_refuse_unbindable_call(policy_.action)
			payload[name] = arguments[name]
		elif name in extra:
			payload[name] = extra[name]
	return payload


def _refuse_unbindable_call(action: str) -> None:
	# no fingerprint and no methods: nothing confirmed can match an underivable payload
	session._raise_confirmation_required(action, methods=[])


def _raise_confirmation_required(policy_: ActionPolicy, params: dict) -> None:
	"""The 401 retry contract with a server-computed fingerprint the client echoes back."""
	session._raise_confirmation_required(
		policy_.action,
		methods=_confirm_methods(frappe.session.user, policy_),
		payload_fingerprint=session.payload_hash(params),
		action_label=_(policy_.display_label) if policy_.display_label else None,
		parameter_summary=_parameter_summary(policy_, params),
	)


def _confirm_methods(user: str, policy_: ActionPolicy) -> list:
	"""The per-user subset of ``passkey`` / ``password`` / ``sudo`` the dialog may offer."""
	methods = []
	if ceremony.enabled_credentials(user):
		methods.append("passkey")
	if policy_.allow_password_fallback and _password_reauth_allowed(user):
		methods.append("password")
	if policy_.allow_sudo_window:
		methods.append("sudo")
	return methods


def _parameter_summary(policy_: ActionPolicy, params: dict) -> list[dict]:
	"""Return only explicitly declared, display-safe parameter values."""
	items = []
	for name, label in policy_.display_params:
		value = params.get(name)
		if isinstance(value, bool):
			value = _("On") if value else _("Off")
		elif value is None:
			value = _("Not set")
		else:
			value = str(value).replace("\r", " ").replace("\n", " ")[:120]
		items.append({"label": _(label), "value": value})
	return items


@frappe.whitelist(methods=["POST"])
def begin_confirmation(action: str, params: object = None, payload_hash: str | None = None):
	"""Mint UV-required assertion options + a ``confirm`` ceremony for ``action``. The
	client sends EITHER raw ``params`` OR the ``payload_hash`` echoed from a prior 401 —
	a hash is never computed client-side. Returns ``{state_id, options,
	payload_fingerprint, methods, action_label, parameter_summary}``."""
	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("begin_confirmation", 30, 300)
	action = _require_action(action)
	if params is not None and payload_hash is not None:
		frappe.throw(_("Send either params or a payload fingerprint, not both."), frappe.ValidationError)
	params = _as_dict(params)
	# A lying echoed hash only mints a grant the consumer's own recomputation rejects.
	fingerprint = str(payload_hash) if payload_hash is not None else session.payload_hash(params or {})

	from passkeys import engine

	settings = frappe.get_cached_doc("Passkey Settings")
	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		raise CeremonyFailed(_("Passkeys aren't set up for this site."))
	origins = policy.resolve_expected_origins(settings, rp_id)
	ceremony.enforce_request_host(origins, error=CeremonyFailed)

	creds = ceremony.enabled_credentials(user)
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id,
		allow_credentials=ceremony.credential_descriptors(creds),
		user_verification=policy.UV_WIRE["confirmation"],
		# the browser gesture must not outlive this ceremony's shorter server-side TTL
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
	action_policy = get_action_policy(action)
	return {
		"state_id": state_id,
		"options": options,
		"payload_fingerprint": fingerprint,
		"methods": _confirm_methods(user, action_policy),
		"action_label": _(action_policy.display_label) if action_policy.display_label else None,
		"parameter_summary": _parameter_summary(action_policy, params) if params is not None else [],
	}


@frappe.whitelist(methods=["POST"])
def verify_confirmation(state_id: str, credential: object):
	"""Verify the confirmation assertion (the UV bit must be 1) and return ``{grant}`` —
	a single-use, 180 s, ``passkey``-method grant bound to user + sid + action +
	payload. Any failure raises the uniform typed error."""
	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("verify_confirmation", 30, 300)

	from passkeys import engine

	credential = ceremony.require_credential_dict(
		credential, _("Passkey could not be verified."), error=CeremonyFailed
	)

	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "confirm":
		raise CeremonyExpired(_("That took too long — please try again."))
	if record.get("user") != user or record.get("sid") != frappe.session.sid:
		raise CeremonyFailed(_("Passkey could not be verified."))

	settings = frappe.get_cached_doc("Passkey Settings")
	ceremony.enforce_request_host(record.get("origins") or [], error=CeremonyFailed)

	cred = ceremony.lock_allowed_credential(record, credential, user, error=CeremonyFailed)
	hard_fail = bool(cint(settings.passkey_sign_count_hard_fail))
	result = engine.verify_stored_assertion(credential, record, cred, sign_count_hard_fail=hard_fail)
	if not result.user_verified:
		raise CeremonyFailed(_("Please verify it's you to confirm this action."))
	# L3 §4: while uv_initialized is false the UV bit is not a factor. The flip needs a
	# password in this session (a password/reauth-seeded window); possession alone never
	# mints a grant.
	uv_flip_pending = not cint(cred.uv_initialized)
	if uv_flip_pending:
		window = session.get_window(user)
		if not (window and window.get("seeded_by") in ("password", "reauth")):
			raise CeremonyFailed(
				_("Passkey confirmation could not be completed. Re-authenticate and begin again.")
			)

	ceremony.advance_credential(
		cred.name,
		result,
		sign_count_hard_fail=hard_fail,
		values={"uv_initialized": 1} if uv_flip_pending else None,
		error=CeremonyFailed,
	)

	token = session.mint_action_grant(user, record["action"], record["payload_hash"], method="passkey")
	# The sudo-gated management endpoints check the window, not the grant. Only the
	# built-in action seeds it: a third-party confirmation never grants management sudo.
	if record.get("action") == session.MANAGE_ACTION:
		session.set_window(user, "passkey")
	return {"grant": token}


@frappe.whitelist(methods=["POST"])
def reauth_password(pwd: str, action: str | None = None, payload_fingerprint: str | None = None):
	"""Password fallback. Without ``action`` it seeds the management sudo window (so
	passkey-less users can enroll); with ``action`` + ``payload_fingerprint`` it mints a
	``password``-method grant, only for an action that declared
	``allow_password_fallback=True``."""
	from frappe.utils.password import check_password

	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("reauth_password", 5, 300)
	# refuse before touching the password oracle
	if not _password_reauth_allowed(user):
		raise CeremonyFailed(
			_("Use your passkey to confirm — password re-authentication is disabled for this account.")
		)

	# Claim atomically before checking the password: the limit-th attempt passes;
	# the next is refused without touching the oracle.
	if state.claim_password_attempt(user) > state.PASSWORD_FAILURE_LIMIT:
		raise CeremonyFailed(_("Too many attempts. Please try again later."))
	try:
		check_password(user, pwd)
	except frappe.AuthenticationError:
		raise CeremonyFailed(_("That password didn't match — try again."))
	state.clear_password_failures(user)

	if action:
		action = _require_action(action)
		policy_ = get_action_policy(action)
		if not policy_.allow_password_fallback:
			raise CeremonyFailed(_("This action requires a passkey — a password can't confirm it."))
		if not payload_fingerprint:
			frappe.throw(_("Missing confirmation payload."), frappe.ValidationError)
		token = session.mint_action_grant(user, action, str(payload_fingerprint), method="password")
		if action == session.MANAGE_ACTION:
			session.set_window(user, "reauth")
		return {"grant": token}

	session.set_window(user, "reauth")
	return {"seeded": True}


def _password_reauth_allowed(user: str) -> bool:
	"""Under ``disable_user_pass_login`` a passkey holder can only confirm with a passkey."""
	return not (
		cint(frappe.get_system_settings("disable_user_pass_login"))
		and frappe.db.exists("WebAuthn Credential", {"user": user, "enabled": 1})
	)


def _require_action(action) -> str:
	action = (action or "").strip() if isinstance(action, str) else action
	if not action or not isinstance(action, str):
		frappe.throw(_("A confirmation action is required."), frappe.ValidationError)
	return action


def _as_dict(value):
	if value is None:
		return None
	try:
		parsed = json.loads(value) if isinstance(value, str) else value
	except (TypeError, ValueError):
		frappe.throw(_("Confirmation parameters must be an object."), frappe.ValidationError)
	if not isinstance(parsed, dict):
		frappe.throw(_("Confirmation parameters must be an object."), frappe.ValidationError)
	return parsed
