# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Desk ``extend_bootinfo`` + per-user enrollment-nudge state.
Folds into ``frappe/passkey.py`` on the core merge.

**Hook-path import discipline:** ``extend_bootinfo`` fires on **every**
Desk boot, so this module MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe`` plus the lightweight
:mod:`passkeys.install` and :mod:`passkeys.policy` modules, all webauthn-free.

Nudge state is stored **exactly the twofactor way**: site-wide
``DefaultValue`` rows with a user-prefixed key under a dedicated parent —
``get_default("{user}_passkey_nudge", parent="__passkeys")`` — never
user-parented ``frappe.defaults`` rows and never on the lazily-created handle
row (a decline must be recordable before any credential exists). Uninstall
deletes every ``parent="__passkeys"`` row (``install.before_uninstall``)."""

import json

import frappe
from frappe.utils import cint, get_datetime, getdate, now_datetime, nowdate

from passkeys import policy
from passkeys.install import DEFAULTS_PARENT, dormant

# record_nudge event vocabulary.
NUDGE_EVENTS = ("shown", "declined", "opt_out")

_EMPTY_NUDGE = {"declines": 0, "last_shown": None, "opt_out": 0}

# record_enforcement event vocabulary. ``defer`` spends one grace login ("Remind me
# later"); ``incapable`` is telemetry only (the user's device cannot create a passkey)
# and folds no counter — the endpoint routes it to the admin advisory.
ENFORCE_EVENTS = ("defer", "incapable")

_EMPTY_ENFORCE = {"grace_used": 0}


def _nudge_key(user: str) -> str:
	return f"{user}_passkey_nudge"


def get_nudge_state(user: str) -> dict:
	"""The user's ``{declines, last_shown, opt_out}`` nudge blob. Absent or
	malformed ⇒ a fresh zero-state (never raises — a bad row must not brick boot)."""
	raw = frappe.db.get_default(_nudge_key(user), parent=DEFAULTS_PARENT)
	if not raw:
		return dict(_EMPTY_NUDGE)
	try:
		data = json.loads(raw)
	except (TypeError, ValueError):
		return dict(_EMPTY_NUDGE)
	if not isinstance(data, dict):
		return dict(_EMPTY_NUDGE)
	return {
		"declines": cint(data.get("declines")),
		"last_shown": data.get("last_shown"),
		"opt_out": cint(data.get("opt_out")),
	}


def _save_nudge_state(user: str, state: dict) -> None:
	frappe.db.set_default(_nudge_key(user), json.dumps(state), parent=DEFAULTS_PARENT)


def record_nudge_event(user: str, event: str) -> dict:
	"""Fold a ``record_nudge`` event into the user's state. ``shown`` is the
	cadence counter event (a network-retried ``shown`` double-increments —
	accepted bounded drift, never gains a prompt); ``declined`` ("Not now") only
	refreshes the cooldown anchor (the preceding ``shown`` already counted);
	``opt_out`` ("Don't ask again") is terminal. Returns the new state."""
	if event not in NUDGE_EVENTS:
		frappe.throw(frappe._("Unknown nudge event."), frappe.ValidationError)
	state = get_nudge_state(user)
	if event == "shown":
		state["declines"] = cint(state.get("declines")) + 1
		state["last_shown"] = now_datetime().isoformat()
	elif event == "declined":
		state["last_shown"] = now_datetime().isoformat()
	elif event == "opt_out":
		state["opt_out"] = 1
	_save_nudge_state(user, state)
	return state


def policy_effective(settings) -> str:
	"""Resolve the ``passkey_enrollment_policy`` Select to an effective rung —
	``off`` | ``nudge`` | ``enforce`` — evaluating ``Enforce After Date`` against the
	server clock on every call (an at/past date ⇒ ``enforce``, before ⇒ ``nudge``; a
	missing date fails safe to ``nudge``, never ``enforce``). A blank/unknown value ⇒
	``nudge`` (behaviour-preserving for a settings row that predates the field, e.g.
	before the migration patch has run)."""
	policy = settings.passkey_enrollment_policy or "Nudge"
	if policy == "Off":
		return "off"
	if policy == "Enforce":
		return "enforce"
	if policy == "Enforce After Date":
		after = settings.passkey_enforce_after
		if after and getdate(after) <= getdate(nowdate()):
			return "enforce"
		return "nudge"
	return "nudge"  # "Nudge" and any unrecognised value


def _enforce_key(user: str) -> str:
	return f"{user}_passkey_enforce"


def get_enforcement_state(user: str) -> dict:
	"""The user's ``{grace_used}`` enforcement blob — how many enrollment prompts they
	have deferred since coming in scope. Stored the twofactor way (site-wide
	``DefaultValue`` under ``__passkeys``), exactly like the nudge state, so a decline
	is recordable before any credential exists. Absent/malformed ⇒ a fresh zero-state."""
	raw = frappe.db.get_default(_enforce_key(user), parent=DEFAULTS_PARENT)
	if not raw:
		return dict(_EMPTY_ENFORCE)
	try:
		data = json.loads(raw)
	except (TypeError, ValueError):
		return dict(_EMPTY_ENFORCE)
	if not isinstance(data, dict):
		return dict(_EMPTY_ENFORCE)
	return {"grace_used": cint(data.get("grace_used"))}


def _save_enforcement_state(user: str, state: dict) -> None:
	frappe.db.set_default(_enforce_key(user), json.dumps(state), parent=DEFAULTS_PARENT)


def record_enforcement_event(user: str, event: str) -> dict:
	"""Fold a ``record_enforcement`` event into the user's grace state. ``defer``
	("Remind me later") spends one grace login. The endpoint claims a per-session
	idempotency key first; the User lock here serializes distinct sessions updating
	the same DefaultValue row. ``incapable`` records no counter (the endpoint handles
	the admin advisory). Returns the new state."""
	if event not in ENFORCE_EVENTS:
		frappe.throw(frappe._("Unknown enforcement event."), frappe.ValidationError)
	if event == "defer":
		frappe.db.get_value("User", user, "name", for_update=True)
	state = get_enforcement_state(user)
	if event == "defer":
		state["grace_used"] = cint(state.get("grace_used")) + 1
	_save_enforcement_state(user, state)
	return state


def clear_enforcement_state(user: str) -> None:
	"""Drop the user's ``{user}_passkey_enforce`` grace blob so their budget is full
	again (``get_enforcement_state`` then serves the fresh zero-state). Deleting the row —
	rather than writing ``grace_used = 0`` — is the canonical reset: absent ≡ zero-state,
	and it leaves no stale row behind. This clears EXACTLY the key
	``record_enforcement_event`` writes and ``build_enforcement`` reads; the separate
	incapable-advisory dedup marker (``notifications``) is not a grace counter and is left
	untouched. The admin grace-reset endpoint is the only caller.

	Uses ``frappe.defaults.clear_default`` (not a raw ``db.delete``) so the delete ALSO
	busts the site-defaults cache — ``get_default`` is cache-served under the same parent,
	so a raw row delete would leave a stale ``grace_used`` reading behind (the mirror of why
	``_save_enforcement_state`` goes through ``set_default``)."""
	frappe.defaults.clear_default(_enforce_key(user), parent=DEFAULTS_PARENT)


def _cadence_ok(settings, state: dict) -> bool:
	"""Shared nudge/upsell cadence. Gated first on the policy rung: the nudge cadence
	only runs while the effective policy is ``nudge`` (``Off`` ⇒ silent; ``Enforce`` /
	post-date ⇒ the enforcement interstitial owns the surface, not the nudge). The
	remaining thresholds come from Passkey Settings knobs (``passkey_nudge_max_prompts``
	/ ``passkey_nudge_cooldown_days`` — never hardcoded): not opted out ∧ declines < cap
	∧ cooldown elapsed. The **credential-count** gate is applied by the caller — the
	enrollment nudge requires 0 credentials, the post-hybrid upsell does not (the user
	just signed in, so they hold ≥1)."""
	if policy_effective(settings) != "nudge":
		return False
	if cint(state.get("opt_out")):
		return False
	if cint(state.get("declines")) >= cint(settings.passkey_nudge_max_prompts):
		return False
	last_shown = state.get("last_shown")
	if last_shown:
		cooldown_days = cint(settings.passkey_nudge_cooldown_days)
		try:
			elapsed = now_datetime() - get_datetime(last_shown)
		except (TypeError, ValueError):
			return True  # unparseable anchor ⇒ treat as no cooldown in force
		if elapsed.total_seconds() < cooldown_days * 86400:
			return False
	return True


def nudge_eligible(user: str, settings, credential_count: int, state: dict | None = None) -> bool:
	"""Server-side enrollment-nudge cadence gate: the shared cadence AND
	``credential_count == 0``. The client ANDs this with its own layered capability
	detection; the server never trusts a client capability claim for cadence."""
	if cint(credential_count) > 0:
		return False
	state = state if state is not None else get_nudge_state(user)
	return _cadence_ok(settings, state)


def upsell_eligible(user: str, settings, state: dict | None = None) -> bool:
	"""Post-hybrid upsell cadence: the shared nudge cadence WITHOUT the
	0-credential gate — the user just completed a hybrid (QR) assertion, so they
	already hold ≥1 credential and ``nudge_state.eligible`` (which requires 0) is the
	wrong signal."""
	state = state if state is not None else get_nudge_state(user)
	return _cadence_ok(settings, state)


def _user_in_enforce_scope(user: str, settings) -> bool:
	"""Whether ``user`` falls within the enforcement scope AND is not exempt. An exempt
	role (``System Manager`` by default) ALWAYS wins — the break-glass guarantee — so it
	is checked before the scope match."""
	roles = set(frappe.get_roles(user))
	exempt = {row.role for row in (settings.passkey_enforce_exempt_roles or [])}
	if roles & exempt:
		return False
	if settings.passkey_enforce_scope == "Selected Roles":
		target = {row.role for row in (settings.passkey_enforce_roles or [])}
		return bool(roles & target)
	return True  # "All Users"


def build_enforcement(user: str, settings, credential_count: int) -> dict:
	"""The server-owned enrollment-enforcement verdict — same trust model as
	``nudge_state`` (scope, date and grace counters live server-side; the client only
	ANDs its device-capability probe). Shape::

	  {
	      policy,
	      effective,
	      in_scope,
	      blocking,
	      grace_remaining,
	      grace_total,
	      allow_hybrid,
	      incapable_policy,
	      reason,
	  }

	``effective`` is the resolved rung (``off``/``nudge``/``enforce``); ``in_scope`` is
	True only when the rung is ``enforce`` AND a passkey login mode is on AND the user
	matches scope and is not exempt; ``blocking`` bites only an in-scope user who still
	has zero passkeys and has exhausted their grace logins. ``incapable_policy``
	(``degrade``/``block_notify``) + ``allow_hybrid`` are the §capability hinge the
	client honors on a device that genuinely cannot create a passkey."""
	effective = policy_effective(settings)
	mode_on = bool(cint(settings.login_with_passkey) or cint(settings.passkey_as_second_factor))
	incapable_policy = (
		"block_notify" if settings.passkey_enforce_incapable == "Block + Notify Admin" else "degrade"
	)
	allow_hybrid = bool(cint(settings.passkey_enforce_allow_hybrid))
	grace_total = cint(settings.passkey_enforce_grace_logins)

	in_scope = effective == "enforce" and mode_on and _user_in_enforce_scope(user, settings)
	# Read the grace counter only for in-scope users (Off/Nudge sites pay nothing).
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
		"reason": reason,
	}


def build_passkeys_boot(user: str) -> dict:
	"""The desk/portal boot payload the management + nudge + settings surfaces read.
	Server state only — no client-supplied value is echoed. This is the single
	contract both the Desk boot flag and the portal ``/passkeys`` controller expose:

	  * ``enabled``            — ANY mode on; the desk navbar + User-form section gate
	    on it (both modes off / dormant ⇒ the management UI removes itself).
	  * ``modes``              — ``{first_factor, second_factor}``.
	  * ``credential_count``   — the user's ENABLED credentials.
	  * ``passkey_only_login`` — the caller's per-user password-login-disable flag
	    (0 when no handle row yet); the management toggle reflects it.
	  * ``nudge_state``        — ``{declines, last_shown, opt_out, eligible}``;
	    ``eligible`` is the SERVER cadence verdict ("never client-side-only caps").
	  * ``post_login_method``  — the sudo window's seeding class this session
	    (``password``/``passkey``/``weak``/``reauth``/``None``); drives the
	    conditional-create (password only) and the fresh-login nudge window.
	  * ``conditional_create`` — the ``passkey_conditional_create`` knob (silent
	    upgrade); the client fails safe OFF when absent.
	  * ``upsell_eligible``    — post-hybrid upsell cadence WITHOUT the 0-credential gate.
	  * ``enforcement``        — the server-owned enforcement verdict
	    ``{policy, effective, in_scope, blocking, grace_remaining, grace_total,
	    allow_hybrid, incapable_policy, reason}`` (see :func:`build_enforcement`); the
	    post-login interstitial reads ``blocking`` the way the banner reads
	    ``nudge_state.eligible``.
	  * ``settings_context``   — ``{core_two_factor_auth, disable_user_pass_login,
	    passkey_only_user_count, would_be_blocked_count}`` for the cross-flag banners +
	    the report-only enforcement preview; System-Manager-only
	    (empty for everyone else — the settings form is admin-only, and the passkey-only
	    user count is not shipped to every Desk boot).
	  * ``rp_id``              — the resolved RP ID for ``signalAllAcceptedCredentials``.
	"""
	settings = frappe.get_cached_doc("Passkey Settings")
	first = bool(cint(settings.login_with_passkey))
	second = bool(cint(settings.passkey_as_second_factor))
	credential_count = frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})
	state = get_nudge_state(user)
	return {
		"enabled": first or second,
		"modes": {"first_factor": first, "second_factor": second},
		"credential_count": credential_count,
		# The caller's own passkey_only_login flag (0 when no handle row) —
		# the desk/portal management toggle reflects it on boot (client parity with
		# list_credentials' payload).
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
		"enforcement": build_enforcement(user, settings, credential_count),
		"settings_context": _settings_context(user, settings),
		"rp_id": policy.resolve_rp_id(settings),
	}


def _settings_context(user: str, settings) -> dict:
	"""Cross-flag banner context (``core_two_factor_auth`` /
	``disable_user_pass_login`` / ``passkey_only_user_count``) plus the report-only
	enforcement preview (``would_be_blocked_count``). Only the Passkey Settings form
	reads it, and that form is System-Manager-only — so this ships an empty dict for
	everyone else (avoids the per-boot count queries + does not expose these counts on
	every Desk load). ``settings.js`` falls back gracefully when the fields are absent."""
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
	"""Report-only preview (System-Manager surface only): how many in-scope users have
	no enabled passkey yet — the blast radius of flipping to ``Enforce``. Uses the
	same role/scope evaluator as runtime enforcement, including automatic roles and
	Administrator. Best-effort — any error ⇒ 0 so the preview can never break the
	settings form or a boot."""
	try:
		enrolled = set(frappe.get_all("WebAuthn Credential", filters={"enabled": 1}, pluck="user"))
		count = 0
		for u in frappe.get_all("User", filters={"enabled": 1}, pluck="name"):
			if u == "Guest":
				continue
			if not _user_in_enforce_scope(u, settings):
				continue
			if u in enrolled:
				continue
			count += 1
		return count
	except Exception:
		return 0


def _post_login_method(user: str) -> str | None:
	from passkeys import session as pk_session

	window = pk_session.get_window(user)
	return window.get("seeded_by") if window else None


def extend_bootinfo(bootinfo=None):
	"""``extend_bootinfo`` hook: publish ``bootinfo.passkeys``. Called by
	``frappe/sessions.py`` as ``extend_bootinfo(bootinfo=bootinfo)``.

	Exception-hardened + ``CORE_NATIVE`` no-op + Guest no-op: this fires on every
	Desk boot, so it must never raise, never import ``webauthn``, and never
	render when core serves passkeys natively (dormant shell)."""
	try:
		if bootinfo is None:
			bootinfo = frappe.local.boot
		if dormant():
			return  # dormant-shell: publish no bootinfo.passkeys, so the desk +
			# portal bundles self-remove on the absent `frappe.boot.passkeys` flag
		user = frappe.session.user
		if not user or user in ("Guest", ""):
			return
		bootinfo.passkeys = build_passkeys_boot(user)
	except Exception:
		frappe.log_error(title="passkeys: extend_bootinfo failed")
