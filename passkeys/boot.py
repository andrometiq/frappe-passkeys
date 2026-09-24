# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Desk ``extend_bootinfo`` plus per-user nudge and enforcement state. Folds into
``frappe/passkey.py`` on the core merge. ``extend_bootinfo`` fires on every Desk boot,
so this module must not import ``webauthn``, directly or transitively.

Per-user state is stored the twofactor way: site-wide ``DefaultValue`` rows keyed
``{user}_passkey_nudge`` / ``{user}_passkey_enforce`` under the ``__passkeys`` parent,
so a decline is recordable before any credential exists."""

import json

import frappe
from frappe.utils import cint, get_datetime, getdate, now_datetime, nowdate

from passkeys import notifications, policy, session
from passkeys.install import DEFAULTS_PARENT, dormant

NUDGE_EVENTS = ("shown", "declined", "opt_out")

_EMPTY_NUDGE = {"declines": 0, "last_shown": None, "opt_out": 0}

# ``defer`` spends one grace login; ``incapable`` folds no counter (admin advisory only).
ENFORCE_EVENTS = ("defer", "incapable")

_EMPTY_ENFORCE = {"grace_used": 0}

# Enrollment-enforcement role policy. The dedicated exemption marker is created
# lazily by enforcement_admin; privileged roles stay in scope by default.
EXEMPT_ROLE = "Passkey Enforcement Exempt"
PRIVILEGED_ROLES = {"System Manager"}


def get_default_value(key: str, *, for_update: bool = False) -> str | None:
	"""Read one ``__passkeys`` row by its exact key, from the database. Never
	``frappe.db.get_default``: it is cache-served, and on a miss it falls back to
	``scrub(key)``, so ``mary-jane@x`` would read ``mary_jane@x``'s row."""
	return frappe.db.get_value(
		"DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": key}, "defvalue", for_update=for_update
	)


def _nudge_key(user: str) -> str:
	return f"{user}_passkey_nudge"


def _load_state(key: str, empty: dict, *, for_update: bool = False) -> dict:
	raw = get_default_value(key, for_update=for_update)
	data = json.loads(raw) if raw else None
	return {**empty, **data} if isinstance(data, dict) else dict(empty)


def _lock_state(user: str, key: str, empty: dict) -> dict:
	"""Read a state row for a read-modify-write: the User lock serializes writers and the
	locking read bypasses a stale transaction snapshot."""
	frappe.db.get_value("User", user, "name", for_update=True)
	return _load_state(key, empty, for_update=True)


def get_nudge_state(user: str) -> dict:
	"""The user's ``{declines, last_shown, opt_out}`` nudge state."""
	return _load_state(_nudge_key(user), _EMPTY_NUDGE)


def record_nudge_event(user: str, event: str) -> dict:
	"""Fold a nudge event into the user's state and return it. ``shown`` counts a prompt
	(a network-retried ``shown`` may double-count — never gains a prompt); ``declined``
	("Not now") only refreshes the cooldown anchor; ``opt_out`` is terminal."""
	if event not in NUDGE_EVENTS:
		frappe.throw(frappe._("Unknown nudge event."), frappe.ValidationError)
	state = _lock_state(user, _nudge_key(user), _EMPTY_NUDGE)
	if event == "shown":
		state["declines"] = cint(state["declines"]) + 1
	if event in ("shown", "declined"):
		state["last_shown"] = now_datetime().isoformat()
	if event == "opt_out":
		state["opt_out"] = 1
	frappe.db.set_default(_nudge_key(user), json.dumps(state), parent=DEFAULTS_PARENT)
	return state


def policy_effective(settings) -> str:
	"""The effective enrollment rung — ``off`` | ``nudge`` | ``enforce``. ``Enforce After
	Date`` is evaluated against the server clock on every call; a missing date stays
	``nudge``, never ``enforce``."""
	policy = settings.passkey_enrollment_policy
	if policy == "Off":
		return "off"
	if policy == "Enforce":
		return "enforce"
	if policy == "Enforce After Date":
		after = settings.passkey_enforce_after
		return "enforce" if after and getdate(after) <= getdate(nowdate()) else "nudge"
	return "nudge"


def _enforce_key(user: str) -> str:
	return f"{user}_passkey_enforce"


def get_enforcement_state(user: str) -> dict:
	"""The user's ``{grace_used}`` state: prompts deferred since coming in scope."""
	return _load_state(_enforce_key(user), _EMPTY_ENFORCE)


def record_enforcement_defer(user: str) -> dict:
	"""Spend one grace login ("Remind me later"); the endpoint first claims a per-session
	idempotency key. Returns the new state."""
	state = _lock_state(user, _enforce_key(user), _EMPTY_ENFORCE)
	state["grace_used"] = cint(state["grace_used"]) + 1
	frappe.db.set_default(_enforce_key(user), json.dumps(state), parent=DEFAULTS_PARENT)
	return state


def clear_enforcement_state(user: str) -> None:
	"""Refill the user's grace budget (the admin grace reset). The incapable-advisory dedup
	marker is not a grace counter and stays."""
	frappe.defaults.clear_default(_enforce_key(user), parent=DEFAULTS_PARENT)


def get_user_state_keys(user: str) -> tuple[str, ...]:
	"""Every per-user ``__passkeys`` key; the User delete and rename cascades walk this."""
	return (_nudge_key(user), _enforce_key(user), notifications.incapable_notify_key(user))


def clear_user_state(user: str) -> None:
	frappe.db.delete(
		"DefaultValue", {"parent": DEFAULTS_PARENT, "defkey": ("in", list(get_user_state_keys(user)))}
	)


def rename_user_state(old: str, new: str, merge: bool) -> None:
	"""Move ``old``'s rows to ``new`` in place; a merge keeps each row the target
	already has. In place, not copy-then-delete: the site collation is case- and
	accent-insensitive, so after a case-only rename both keys match the same row."""
	for old_key, new_key in zip(get_user_state_keys(old), get_user_state_keys(new), strict=True):
		old_row = {"parent": DEFAULTS_PARENT, "defkey": old_key}
		if merge and get_default_value(new_key) is not None:
			frappe.db.delete("DefaultValue", old_row)
		else:
			frappe.db.set_value("DefaultValue", old_row, "defkey", new_key, update_modified=False)


def _cadence_ok(settings, state: dict) -> bool:
	"""Shared nudge/upsell cadence: a login mode is on, the effective rung is ``nudge``
	(under ``enforce`` the interstitial owns the surface), and the thresholds hold. The
	caller applies any credential-count gate."""
	if not (cint(settings.login_with_passkey) or cint(settings.passkey_as_second_factor)):
		return False
	if policy_effective(settings) != "nudge":
		return False
	return _nudge_thresholds_ok(settings, state)


def _nudge_thresholds_ok(settings, state: dict) -> bool:
	"""Opt-out, prompt cap and cooldown shared by ordinary and degraded nudges."""
	if cint(state["opt_out"]) or cint(state["declines"]) >= cint(settings.passkey_nudge_max_prompts):
		return False
	last_shown = state["last_shown"]
	cooldown_seconds = cint(settings.passkey_nudge_cooldown_days) * 86400
	return not last_shown or (now_datetime() - get_datetime(last_shown)).total_seconds() >= cooldown_seconds


def nudge_eligible(user: str, settings, credential_count: int, state: dict | None = None) -> bool:
	"""Enrollment-nudge cadence for a user with no passkey. The client ANDs its own
	capability detection; cadence is never a client claim."""
	if cint(credential_count) > 0:
		return False
	state = state if state is not None else get_nudge_state(user)
	return _cadence_ok(settings, state)


def upsell_eligible(user: str, settings, state: dict | None = None) -> bool:
	"""Post-hybrid (QR) upsell cadence: the nudge cadence without the zero-credential
	gate, since the user just signed in with a passkey."""
	state = state if state is not None else get_nudge_state(user)
	return _cadence_ok(settings, state)


def assigned_roles(user: str) -> set[str]:
	"""Roles on the user's Has Role rows.

	``frappe.get_roles("Administrator")`` returns every Role, so the exempt marker
	or a selected role would match Administrator as soon as the Role exists."""
	return set(
		frappe.get_all(
			"Has Role",
			filters={"parent": user, "parenttype": "User"},
			pluck="role",
		)
	)


def _user_in_enforce_scope(user: str, settings) -> bool:
	"""The exemption marker role wins; then privileged roles when that safeguard is on;
	then Selected Roles; otherwise All Users. Administrator is privileged."""
	roles = assigned_roles(user)
	if EXEMPT_ROLE in roles:
		return False
	privileged = user == "Administrator" or bool(roles & PRIVILEGED_ROLES)
	if cint(settings.passkey_enforce_privileged_always) and privileged:
		return True
	if settings.passkey_enforce_scope == "Selected Roles":
		target = {row.role for row in (settings.passkey_enforce_roles or [])}
		return bool(roles & target)
	return True  # "All Users"


def build_enforcement(user: str, settings, credential_count: int, nudge_state: dict | None = None) -> dict:
	"""The server-owned enforcement verdict; the client only ANDs its device-capability
	probe. ``in_scope`` needs the ``enforce`` rung, a login mode and a scope match;
	``blocking`` bites an in-scope user with no passkey and no grace left.
	``incapable_policy`` + ``allow_hybrid`` govern a device that cannot create a passkey;
	``degrade_nudge_eligible`` applies the nudge thresholds to such a user under Degrade."""
	effective = policy_effective(settings)
	mode_on = bool(cint(settings.login_with_passkey) or cint(settings.passkey_as_second_factor))
	incapable_policy = (
		"block_notify" if settings.passkey_enforce_incapable == "Block + Notify Admin" else "degrade"
	)
	allow_hybrid = bool(cint(settings.passkey_enforce_allow_hybrid))
	grace_total = cint(settings.passkey_enforce_grace_logins)

	in_scope = effective == "enforce" and mode_on and _user_in_enforce_scope(user, settings)
	# only in-scope users pay the grace read
	grace_used = cint(get_enforcement_state(user)["grace_used"]) if in_scope else 0
	grace_remaining = max(0, grace_total - grace_used) if in_scope else grace_total
	blocking = in_scope and credential_count == 0 and grace_remaining == 0

	if not in_scope:
		reason = "not_in_scope" if effective == "enforce" else effective
	elif credential_count > 0:
		reason = "satisfied"
	elif blocking:
		reason = "blocking"
	else:
		reason = "grace"

	return {
		"policy": settings.passkey_enrollment_policy or "Nudge",
		"effective": effective,
		"in_scope": in_scope,
		"blocking": blocking,
		"grace_remaining": grace_remaining,
		"grace_total": grace_total,
		"allow_hybrid": allow_hybrid,
		"incapable_policy": incapable_policy,
		"degrade_nudge_eligible": (
			in_scope
			and credential_count == 0
			and incapable_policy == "degrade"
			and _nudge_thresholds_ok(
				settings, nudge_state if nudge_state is not None else get_nudge_state(user)
			)
		),
		"reason": reason,
	}


def build_passkeys_boot(user: str, *, include_settings_context: bool = False) -> dict:
	"""The ``frappe.boot.passkeys`` contract shared by the Desk boot and the portal
	``/passkeys`` page: server state only, never an echoed client value. ``enabled`` (any
	mode on) gates the management UI; ``post_login_method`` is this session's sudo-window
	class; ``settings_context`` is filled only for a System Manager's Desk boot, because
	its preview count evaluates every enabled user's roles."""
	settings = frappe.get_cached_doc("Passkey Settings")
	first = bool(cint(settings.login_with_passkey))
	second = bool(cint(settings.passkey_as_second_factor))
	credential_count = frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})
	state = get_nudge_state(user)
	return {
		"enabled": first or second,
		"modes": {"first_factor": first, "second_factor": second},
		"credential_count": credential_count,
		"passkey_only_login": cint(
			frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login")
		),
		"nudge_state": {
			**state,
			"eligible": nudge_eligible(user, settings, credential_count, state),
		},
		"post_login_method": _post_login_method(user),
		"conditional_create": bool(cint(settings.passkey_conditional_create)),
		"upsell_eligible": upsell_eligible(user, settings, state),
		"enforcement": build_enforcement(user, settings, credential_count, state),
		"settings_context": _settings_context(user, settings) if include_settings_context else {},
		"rp_id": policy.resolve_rp_id(settings),
	}


def _settings_context(user: str, settings) -> dict:
	"""Banner context and the enforcement preview for the System-Manager-only Passkey
	Settings form; empty for everyone else."""
	if "System Manager" not in frappe.get_roles(user):
		return {}
	return {
		"core_two_factor_auth": bool(cint(frappe.get_system_settings("enable_two_factor_auth"))),
		"disable_user_pass_login": bool(cint(frappe.get_system_settings("disable_user_pass_login"))),
		"configured_site_origin": policy.resolve_site_origin(policy.resolve_rp_id(settings) or ""),
		"passkey_only_user_count": frappe.db.count("WebAuthn User Handle", {"passkey_only_login": 1}),
		"would_be_blocked_count": _would_be_blocked_count(settings),
	}


def _would_be_blocked_count(settings) -> int:
	"""How many in-scope enabled users have no enabled passkey — the blast radius of
	switching to ``Enforce``, by the same scope evaluator as runtime enforcement."""
	enrolled = set(frappe.get_all("WebAuthn Credential", filters={"enabled": 1}, pluck="user"))
	users = frappe.get_all("User", filters={"enabled": 1}, pluck="name")
	return sum(
		1
		for user in users
		if user != "Guest" and user not in enrolled and _user_in_enforce_scope(user, settings)
	)


def _post_login_method(user: str) -> str | None:
	window = session.get_window(user)
	return window.get("seeded_by") if window else None


def extend_bootinfo(bootinfo):
	"""``extend_bootinfo`` hook: publish ``bootinfo.passkeys``. Never raises. A dormant
	shell publishes nothing, so the client bundles remove themselves."""
	try:
		if dormant():
			return
		user = frappe.session.user
		if not user or user in ("Guest", ""):
			return
		bootinfo.passkeys = build_passkeys_boot(user, include_settings_context=True)
	except Exception:
		frappe.log_error(title="passkeys: extend_bootinfo failed")
