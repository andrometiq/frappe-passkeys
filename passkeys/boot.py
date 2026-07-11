# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Desk ``extend_bootinfo`` + per-user enrollment-nudge state.
Folds into ``frappe/passkey.py`` on the core merge.

**Hook-path import discipline:** ``extend_bootinfo`` fires on **every**
Desk boot, so this module MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe`` and :mod:`passkeys.install` (the
``CORE_NATIVE`` switch + the ``__passkeys`` Defaults parent), both webauthn-free.

Nudge state is stored **exactly the twofactor way**: site-wide
``DefaultValue`` rows with a user-prefixed key under a dedicated parent —
``get_default("{user}_passkey_nudge", parent="__passkeys")`` — never
user-parented ``frappe.defaults`` rows and never on the lazily-created handle
row (a decline must be recordable before any credential exists). Uninstall
deletes every ``parent="__passkeys"`` row (``install.before_uninstall``)."""

import json

import frappe
from frappe.utils import cint, get_datetime, now_datetime

from passkeys.install import DEFAULTS_PARENT, dormant

# record_nudge event vocabulary.
NUDGE_EVENTS = ("shown", "declined", "opt_out")

_EMPTY_NUDGE = {"declines": 0, "last_shown": None, "opt_out": 0}


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


def _cadence_ok(settings, state: dict) -> bool:
	"""Shared nudge/upsell cadence. All thresholds come from Passkey Settings
	knobs (``passkey_enrollment_nudge`` / ``passkey_nudge_max_prompts`` /
	``passkey_nudge_cooldown_days`` — never hardcoded): knob on ∧
	not opted out ∧ declines < cap ∧ cooldown elapsed. The **credential-count** gate
	is applied by the caller — the enrollment nudge requires 0 credentials, the
	post-hybrid upsell does not (the user just signed in, so they hold ≥1)."""
	if not cint(settings.passkey_enrollment_nudge):
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
	  * ``settings_context``   — ``{core_two_factor_auth, disable_user_pass_login,
	    passkey_only_user_count}`` for the cross-flag banners; System-Manager-only
	    (empty for everyone else — the settings form is admin-only, and the passkey-only
	    user count is not shipped to every Desk boot).
	  * ``rp_id``              — the resolved RP ID for ``signalAllAcceptedCredentials``.
	"""
	from passkeys import policy  # webauthn-free (frappe-only); safe on the boot path

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
		"settings_context": _settings_context(user),
		"rp_id": policy.resolve_rp_id(settings),
	}


def _settings_context(user: str) -> dict:
	"""Cross-flag banner context (``core_two_factor_auth`` /
	``disable_user_pass_login`` / ``passkey_only_user_count``). Only the Passkey
	Settings form reads it, and that form is System-Manager-only — so this ships an
	empty dict for everyone else (avoids the per-boot count query + not exposing the
	passkey-only user count on every Desk load). ``settings.js`` falls back gracefully
	when the fields are absent."""
	if "System Manager" not in frappe.get_roles(user):
		return {}
	return {
		"core_two_factor_auth": bool(cint(frappe.get_system_settings("enable_two_factor_auth"))),
		"disable_user_pass_login": bool(cint(frappe.get_system_settings("disable_user_pass_login"))),
		"passkey_only_user_count": frappe.db.count("WebAuthn User Handle", {"passkey_only_login": 1}),
	}


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
