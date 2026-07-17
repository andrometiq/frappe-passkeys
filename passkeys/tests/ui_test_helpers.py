# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted helpers the Cypress login specs (`cypress/integration/*.cy.js`)
call via ``cy.call`` to set up + tear down server state on the shared UI-test
site. Mirrors ``frappe/tests/ui_test_helpers.py``: POST-only and admin-only,
with explicit test-site configuration required outside the test runner. The one
exception is ``slow_guest_echo`` (guest + GET), needed to pin the sid re-seed
race; it is kept safe by flag-gating + a capped no-op body (see its docstring
and ``test_all_test_helper_whitelists_are_post_only``).

These are the app's **test scaffolding only** — they fold away with the
``shims/`` on the core merge. They set Passkey Settings values **directly**
(``set_single_value``) rather than through ``Passkey Settings.validate``: the
enable-time validator refuses an ``http://`` origin unless developer mode is on,
but the runtime login path (``resolve_origins`` + the library's
``expected_origin`` check) accepts whatever origin list is stored — so a
``*.localhost`` UI-test bench works without threading developer-mode through the
DocType validator. ``webauthn`` is never imported here (hook-path
discipline is not at stake, but the parity is cheap)."""

import functools
import time

import frappe
from frappe.utils import cint

from passkeys.tests.compat import flush_settings_cache


def _guard() -> None:
	"""Admin-only; require explicit development and test-site flags outside tests."""
	frappe.only_for("System Manager")
	if getattr(frappe.flags, "in_test", False):
		return
	if not (cint(frappe.conf.get("developer_mode")) and cint(frappe.conf.get("allow_tests"))):
		frappe.throw(
			"passkeys UI-test helpers require test mode or both developer_mode and allow_tests",
			frappe.ValidationError,
		)


def _guarded_test_helper(fn):
	"""Run the test-site guard before any inner endpoint decorator."""

	@functools.wraps(fn)
	def guarded(*args, **kwargs):
		_guard()
		return fn(*args, **kwargs)

	return guarded


@frappe.whitelist(methods=["POST"])
def configure_login(
	rp_id: str,
	origin: str,
	login_with_passkey: int = 1,
	passkey_as_second_factor: int = 0,
) -> dict:
	"""Point Passkey Settings at the UI-test site's RP ID + origin and toggle the
	login modes. Values are written directly so the ``http://*.localhost`` origin
	is accepted regardless of the enable-time HTTPS validator (see module docstring)."""
	_guard()
	values = {
		"passkey_rp_id": rp_id,
		"passkey_origins": origin,
		"login_with_passkey": cint(login_with_passkey),
		"passkey_as_second_factor": cint(passkey_as_second_factor),
	}
	for field, value in values.items():
		frappe.db.set_single_value("Passkey Settings", field, value)
	flush_settings_cache()
	frappe.db.commit()
	return values


_2FA_ROLE = "Passkey 2FA UI Role"


@frappe.whitelist(methods=["POST"])
def configure_second_factor(
	rp_id: str,
	origin: str,
	login_with_passkey: int = 0,
	allow_otp_fallback: int = 0,
) -> dict:
	"""Set up the password → passkey second-factor mode for the Cypress spec:
	turn core Two Factor Authentication ON (the structural floor), point
	Passkey Settings at the UI-test origin, and enable
	``passkey_as_second_factor`` + the OTP-fallback knob. Values are written
	directly (``set_single_value``) — the same bench-origin rationale as
	:func:`configure_login`, and ``set_single_value`` bypasses the doc_events
	floor guard, which is correct for scaffolding."""
	_guard()
	frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
	frappe.db.set_single_value("System Settings", "two_factor_method", "OTP App")
	values = {
		"passkey_rp_id": rp_id,
		"passkey_origins": origin,
		"login_with_passkey": cint(login_with_passkey),
		"passkey_as_second_factor": 1,
		"passkey_2fa_allow_otp_fallback": cint(allow_otp_fallback),
	}
	for field, value in values.items():
		frappe.db.set_single_value("Passkey Settings", field, value)
	frappe.local.system_settings = None
	frappe.clear_document_cache("System Settings", "System Settings")
	flush_settings_cache()
	frappe.db.commit()
	return values


@frappe.whitelist(methods=["POST"])
def teardown_second_factor() -> dict:
	"""Undo :func:`configure_second_factor` (spec ``after``): drop the app
	second-factor mode, then core 2FA. ``set_single_value`` bypasses the
	doc_events guard (which would otherwise block the 1→0 flip), so order is
	immaterial — clear the app knob first for clarity."""
	_guard()
	frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
	frappe.db.set_single_value("Passkey Settings", "passkey_2fa_allow_otp_fallback", 0)
	frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 0)
	frappe.local.system_settings = None
	frappe.clear_document_cache("System Settings", "System Settings")
	flush_settings_cache()
	frappe.db.commit()
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def ensure_second_factor_user(email: str, pwd: str) -> str:
	"""Get or create a non-admin test user with a known password."""
	_guard()
	from frappe.utils.password import update_password

	if not frappe.db.exists("User", email):
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "Passkey",
				"last_name": "SecondFactor",
				"send_welcome_email": 0,
			}
		)
		user.flags.no_welcome_mail = True
		user.insert(ignore_permissions=True)
	update_password(email, pwd)
	frappe.db.commit()
	return email


@frappe.whitelist(methods=["POST"])
def enroll_user_in_2fa(user: str) -> dict:
	"""Cover ``user`` with a role carrying ``two_factor_auth=1`` so
	``should_run_2fa(user)`` is True (drives pwd retention + OTP fallback), and
	force the OTP-App verification path off the email branch. Call AFTER the
	passkey is registered — a 2FA-covered ``/api/method/login`` would otherwise
	trip core OTP mid-registration."""
	_guard()
	from frappe.twofactor import set_default

	if not frappe.db.exists("Role", _2FA_ROLE):
		frappe.get_doc(
			{"doctype": "Role", "role_name": _2FA_ROLE, "two_factor_auth": 1, "desk_access": 0}
		).insert(ignore_permissions=True)
	frappe.get_doc("User", user).add_roles(_2FA_ROLE)
	set_default(user + "_otplogin", 1)
	frappe.db.commit()
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def delete_test_user(email: str) -> dict:
	"""Remove a user created by :func:`ensure_second_factor_user` (spec cleanup)."""
	_guard()
	frappe.db.delete("WebAuthn Credential", {"user": email})
	frappe.db.delete("WebAuthn User Handle", {"user": email})
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=1, ignore_permissions=True, delete_permanently=True)
	frappe.db.commit()
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def purge_passkeys(user: str) -> dict:
	"""Delete every WebAuthn Credential + User Handle row for ``user``."""
	_guard()
	deleted = frappe.db.count("WebAuthn Credential", {"user": user})
	frappe.db.delete("WebAuthn Credential", {"user": user})
	frappe.db.delete("WebAuthn User Handle", {"user": user})
	frappe.db.commit()
	return {"deleted": deleted}


@frappe.whitelist(methods=["POST"])
def clear_registration_rate_limit(user: str) -> dict:
	"""Clear the test-setup registration throttles for ``user``.

	Cypress specs call the real registration ceremony many times while seeding
	fixtures. The production limit is still tested below the API layer; this helper
	only keeps repeated local UI-suite runs from depending on Redis TTL expiry."""
	_guard()
	from passkeys import state

	for method in ("begin_registration", "verify_registration"):
		state.clear_counter(f"{state.RATE_LIMIT_PREFIX}{method}:{user}")
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def clear_password_failures(user: str) -> dict:
	"""Clear the app-owned password-oracle throttle for ``user``.

	UI specs that intentionally exercise wrong-password or interrupted password
	step-up paths run repeatedly on a shared bench. The production throttle remains
	covered in server tests; this helper keeps setup from depending on Redis TTLs."""
	_guard()
	from passkeys import state

	state.clear_password_failures(user)
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def clear_guest_ceremony_rate_limit() -> dict:
	"""Clear frappe's IP-keyed ``@rate_limit`` counters for the guest passkey
	ceremony endpoints (``begin_login`` and ``get_app_translations`` at 30/min/IP,
	and ``verify_login`` at 10/min/IP).

	Every Cypress spec runs from the same CI runner IP against one shared bench,
	and each login-page visit fires ``begin_login`` (button-config channel) plus
	``get_app_translations``; across the suite that shared-IP 60s window fills
	up, so a spec that runs late (``passkey_uv_setup`` is #18 of 19) 429s on
	``begin_login`` and the step-up dialog never opens. The production limits stay
	covered in server tests (``test_login_api``); this only keeps repeated
	same-IP UI runs from depending on Redis TTL expiry. Wildcard-clears every
	identity, so it is robust to how the proxy presents the client IP."""
	_guard()

	for method in (
		"passkeys.passkey.begin_login",
		"passkeys.passkey.verify_login",
		"passkeys.passkey.get_app_translations",
	):
		frappe.cache.delete_keys(f"rl:{method}:")
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def make_uv_uninitialized(user: str) -> dict:
	"""Force ``uv_initialized=0`` on the user's credential(s) so a UV=1 assertion
	drives the uv-setup step-up (the conditional-create-born state, produced
	server-side without needing a conditional-create browser ceremony)."""
	_guard()
	names = frappe.get_all("WebAuthn Credential", filters={"user": user}, pluck="name")
	for name in names:
		frappe.db.set_value("WebAuthn Credential", name, "uv_initialized", 0, update_modified=False)
	frappe.db.commit()
	return {"updated": names}


@frappe.whitelist(methods=["POST"])
def credential_count(user: str) -> int:
	"""Server-side truth for a spec's post-condition assertions."""
	_guard()
	return frappe.db.count("WebAuthn Credential", {"user": user})


# ---------------------------------------------------------------------------
# management + nudge helpers — the sudo-gate delete dance
# (manage_user_form.cy.js) and the nudge-cadence spec (nudge_cadence.cy.js) drive
# these via cy.call. The FRONTEND agent cannot add Python, so integration owns
# them. Test-only; fold away with the shims.
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def clear_sudo_window() -> dict:
	"""Expire the caller's fresh-login sudo window so a sudo-gated mutation must
	re-confirm. Drives ``manage_user_form.cy.js``."""
	_guard()
	from passkeys import state

	state.clear_sudo_window(frappe.session.sid)
	return {"ok": 1}


@frappe.whitelist(methods=["POST"])
def configure_nudge(
	enrollment_nudge: int = 1,
	max_prompts: int = 3,
	cooldown_days: int = 30,
	conditional_create: int = 0,
) -> dict:
	"""Set the enrollment-nudge knobs for ``nudge_cadence.cy.js`` (written
	directly — the same bench rationale as :func:`configure_login`). The legacy
	``enrollment_nudge`` flag maps onto the ``passkey_enrollment_policy`` ladder
	(1 ⇒ ``Nudge``, 0 ⇒ ``Off``)."""
	_guard()
	values = {
		"passkey_enrollment_policy": "Nudge" if cint(enrollment_nudge) else "Off",
		"passkey_nudge_max_prompts": cint(max_prompts),
		"passkey_nudge_cooldown_days": cint(cooldown_days),
		"passkey_conditional_create": cint(conditional_create),
	}
	for field, value in values.items():
		frappe.db.set_single_value("Passkey Settings", field, value)
	flush_settings_cache()
	frappe.db.commit()
	return values


@frappe.whitelist(methods=["POST"])
def seed_nudge_state(declines: int = 0, last_shown=None, opt_out: int = 0) -> dict:
	"""Write the caller's ``{user}_passkey_nudge`` Defaults row directly (idiom)
	so a spec can drive a specific cadence state. Drives ``nudge_cadence.cy.js``."""
	_guard()
	from passkeys.install import DEFAULTS_PARENT

	blob = {"declines": cint(declines), "last_shown": last_shown or None, "opt_out": cint(opt_out)}
	frappe.db.set_default(
		f"{frappe.session.user}_passkey_nudge", frappe.as_json(blob), parent=DEFAULTS_PARENT
	)
	frappe.db.commit()
	return blob


@frappe.whitelist(methods=["POST"])
def get_nudge_state() -> dict:
	"""Read the caller's server-side nudge state back for a spec's post-condition
	assertions. Drives ``nudge_cadence.cy.js``."""
	_guard()
	from passkeys import boot

	return boot.get_nudge_state(frappe.session.user)


# ---------------------------------------------------------------------------
# action-confirmation ("passkey signing") probes — the decorated endpoints the
# confirm Cypress specs drive through the frozen `frappe.passkeys.*` client.
# These import `passkeys.confirm` (webauthn-free) and register their actions at
# import time — pure test scaffolding, folds away with the shims on core merge.
# ---------------------------------------------------------------------------

from passkeys.confirm import passkey_protected

# Namespaced probe actions (never collide with the app's own passkeys.* actions).
CONFIRM_PROBE_ACTION = "passkeys.tests.confirm_probe"
CONFIRM_PROBE_PASSKEY_ONLY_ACTION = "passkeys.tests.confirm_probe_passkey_only"
CONFIRM_PROBE_FAILING_ACTION = "passkeys.tests.confirm_probe_failing"


@frappe.whitelist(methods=["POST"])
@_guarded_test_helper
@passkey_protected(action=CONFIRM_PROBE_ACTION, bind_params=["token"], allow_password_fallback=True)
def confirm_probe(token=None) -> dict:
	"""A @passkey_protected endpoint the confirm-happy / call-retry / password-
	fallback / concurrency specs hit: a valid grant for ``(action, {token})`` runs
	it; otherwise it 401s the retry contract. ``allow_password_fallback=True`` so
	the password tab is offered."""
	return {"confirmed": True, "token": token}


@frappe.whitelist(methods=["POST"])
@_guarded_test_helper
@passkey_protected(
	action=CONFIRM_PROBE_PASSKEY_ONLY_ACTION, bind_params=["token"], allow_password_fallback=False
)
def confirm_probe_passkey_only(token=None) -> dict:
	"""Passkey-only assurance variant (``allow_password_fallback=False``): the
	error-taxonomy spec asserts the dialog offers no password door and a password
	grant never satisfies it."""
	return {"confirmed": True, "token": token}


@frappe.whitelist(methods=["POST"])
@_guarded_test_helper
@passkey_protected(action=CONFIRM_PROBE_FAILING_ACTION, bind_params=["token"])
def confirm_probe_failing(token=None):
	"""Consumes the grant, then fails — the grant-semantics spec asserts the
	gesture is burned even when the wrapped action fails: a retry needs a
	fresh ceremony."""
	frappe.throw("intentional post-consume failure (A-F20 probe)", frappe.ValidationError)


@frappe.whitelist(allow_guest=True)
def slow_guest_echo(delay: float = 1.5) -> dict:
	"""A deliberately slow no-op, used by ``sid_reseed_race.cy.js`` to make the
	straggler-response sid races deterministic (see ``cookie_determinism.py``).

	Deliberately breaks this module's POST-only + admin-only convention: the
	race being pinned is precisely "a request sent under a previous auth state
	responds late", so the spec must fire it as Guest (and as a plain GET —
	an authenticated test-jar POST would be rejected for a missing CSRF token
	before reaching the handler). Instead of :func:`_guard` it is gated on the
	deterministic-cookie site flag OR a developer_mode+allow_tests site — the
	looser half exists so a control run can reproduce the race with the hook
	off; the sleep is capped so even a misconfigured site is not a useful
	stall primitive."""
	if not (
		frappe.conf.get("passkeys_deterministic_test_cookies")
		or (cint(frappe.conf.get("developer_mode")) and cint(frappe.conf.get("allow_tests")))
	):
		frappe.throw(
			"slow_guest_echo requires the passkeys_deterministic_test_cookies site flag",
			frappe.ValidationError,
		)
	time.sleep(min(float(delay), 5.0))
	return {"ok": 1, "user": frappe.session.user}
