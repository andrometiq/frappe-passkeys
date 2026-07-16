# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Browserless WebAuthn TEST MODE — a bench-guarded fake-service layer that runs
**real** ceremonies (real challenges, the unmodified ``py_webauthn`` verifier, and
every app-side check) driven by the deterministic :class:`SoftAuthenticator`
instead of a browser + CDP virtual authenticator.

It exists so this app — and any app that adopts it — can test the full
register → login → delete pipeline in a plain ``bench run-tests`` without Cypress /
Chromium. In the ``ui_test_helpers`` mould: **test scaffolding only**, folding away
with the ``shims/`` on the core merge.

Security posture — the map's musts, each honoured here:

1. **Disabled under production defaults.** Every whitelisted entry point calls
   :func:`_guard` first. Outside the test runner it requires a System Manager on a
   site with both ``developer_mode`` and ``allow_tests`` enabled, matching
   ``ui_test_helpers._guard``. A fake ceremony that mints a session on a live site
   would be a full auth bypass. The internal ``_*_ceremony`` helpers run only *after*
   a public entry has guarded.
2. **Never shipped on a hook path, never Guest-reachable.** This module is on no
   ``hooks.py`` chain and no endpoint is ``allow_guest``; it is reachable only by a
   System Manager on a dev/test bench (or imported directly by a test).
3. **No skip-verification branch — anywhere.** Nothing here touches
   :mod:`passkeys.engine`. The :class:`SoftAuthenticator` emits spec-valid L3 JSON
   that passes the *unmodified* verifier; a tampered payload is still rejected
   (``test_fake_webauthn`` proves it). There is no "test-only accept" door.
4. **Only the enable-time HTTPS validator is relaxed.** :func:`enable` writes
   settings directly (``set_single_value``), exactly like
   ``ui_test_helpers.configure_login``, so an ``http://*.localhost`` origin is
   accepted without threading developer mode through ``Passkey Settings.validate`` —
   while the **ceremony-time** ``expected_origin`` check stays fully intact.
5. **Deterministic test keys require explicit test-site configuration.** The
   :class:`SoftAuthenticator` is seed-derived (labelled test keys) and is only ever
   invoked behind :func:`_guard`.
"""

import frappe
from frappe.auth import CookieManager
from frappe.utils import cint, set_request

from passkeys import passkey, state
from passkeys.api import credentials, registration
from passkeys.tests.compat import flush_settings_cache
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import ES256, SoftAuthenticator, b64url_decode

DEFAULT_RP_ID = "example.com"
DEFAULT_ORIGIN = "https://example.com"


def _guard() -> None:
	"""Admin-only; require explicit development and test-site flags outside tests."""
	frappe.only_for("System Manager")
	if getattr(frappe.flags, "in_test", False):
		return
	if not (cint(frappe.conf.get("developer_mode")) and cint(frappe.conf.get("allow_tests"))):
		frappe.throw(
			"passkeys browserless test mode requires test mode or both developer_mode and allow_tests",
			frappe.ValidationError,
		)


@frappe.whitelist(methods=["POST"])
def enable(rp_id: str = DEFAULT_RP_ID, origin: str = DEFAULT_ORIGIN, second_factor: int = 0) -> dict:
	"""Point Passkey Settings at a browserless test RP + origin and turn login on.

	Written **directly** (``set_single_value``) so a non-HTTPS ``*.localhost`` origin
	is accepted regardless of the enable-time HTTPS validator (the test-mode
	relaxation, must #4) — the runtime ``expected_origin`` check the ceremony engine
	enforces is untouched."""
	_guard()
	values = {
		"passkey_rp_id": rp_id,
		"passkey_origins": origin,
		"login_with_passkey": 1,
		"passkey_as_second_factor": cint(second_factor),
	}
	for field, value in values.items():
		frappe.db.set_single_value("Passkey Settings", field, value)
	flush_settings_cache()
	return values


@frappe.whitelist(methods=["POST"])
def enroll(
	user: str | None = None,
	seed: str = "primary",
	alg: int = ES256,
	rp_id: str = DEFAULT_RP_ID,
	origin: str = DEFAULT_ORIGIN,
	label: str | None = None,
	uv: int = 1,
) -> dict:
	"""Enrol a real passkey for ``user`` (default: the current session user) without a
	browser, and **commit** it so a subsequent HTTP call / browser session sees it —
	the standalone primitive an integrator's Cypress spec can ``cy.call`` to seed a
	credential, or a bench test can call to give a user a passkey.

	Guarded once at entry (System Manager on a dev/test bench); the ceremony then runs
	*as the target user* — identity is derived from the session, never a ceremony
	param (the A1 discipline), so enrolling for another user switches the session
	internally and restores it. Returns ``{name, credential_id, handle, seed, alg}``."""
	_guard()
	prior = frappe.session.user
	target = user or prior
	switched = target != prior
	try:
		if switched:
			frappe.set_user(target)
		reg = _register_ceremony(seed, cint(alg), rp_id, origin, label, bool(cint(uv)))
	finally:
		if switched:
			frappe.set_user(prior)
	frappe.db.commit()
	return reg


@frappe.whitelist(methods=["POST"])
def round_trip(
	seed: str | None = None,
	alg: int = ES256,
	rp_id: str = DEFAULT_RP_ID,
	origin: str = DEFAULT_ORIGIN,
) -> dict:
	"""A full browserless **register → login → delete** round-trip through the REAL
	verify paths, on a throwaway user — the deliverable test's driver AND a one-call
	smoke test an integrator can run against their own bench.

	Self-contained: it creates + cleans its own user. ``verify_login`` mints a session
	via ``login_as``, which **commits** mid-flow, so the cleanup commits too and the
	Administrator session is restored in ``finally``. Returns a structured report."""
	_guard()
	seed = seed or f"round-trip-{frappe.generate_hash(length=8)}"
	alg = cint(alg)
	user = make_user()
	report = {"user": user, "seed": seed, "alg": alg}
	try:
		enable(rp_id=rp_id, origin=origin)

		# 1. REGISTER — real ceremony as the throwaway user.
		frappe.set_user(user)
		reg = _register_ceremony(seed, alg, rp_id, origin, None, uv=True)
		report["registered"] = reg["name"]
		report["credential_id"] = reg["credential_id"]

		# The server minted a RANDOM user handle; align the authenticator onto it so the
		# discoverable login resolves this account (as a real platform authenticator would).
		auth = SoftAuthenticator(alg=alg, seed=seed)
		auth.user_handle = b64url_decode(reg["handle"])

		# 2. LOGIN — discoverable, no identifier; mints a session for the resolved user.
		frappe.set_user("Guest")
		resolved = _login_ceremony(auth, rp_id, origin, sign_count=5)
		report["logged_in_as"] = resolved
		report["session_matches"] = resolved == user
		report["sign_count"] = frappe.db.get_value("WebAuthn Credential", reg["name"], "sign_count")

		# 3. DELETE — the sudo-gated management endpoint; the login seeded a full "passkey"
		#    window, so require_management_sudo is satisfied without a second re-auth.
		deleted = credentials.delete_credential(reg["name"])
		report["deleted"] = deleted["deleted"]
		report["credential_gone"] = not frappe.db.exists("WebAuthn Credential", reg["name"])
		return report
	finally:
		frappe.set_user("Administrator")
		frappe.db.delete("WebAuthn Credential", {"user": user})
		frappe.db.delete("WebAuthn User Handle", {"user": user})
		if frappe.db.exists("User", user):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()  # durable past the caller's per-test rollback (login_as committed)


# ---------------------------------------------------------------------------
# internal ceremonies — unguarded, run only after a public entry has guarded.
# ---------------------------------------------------------------------------


def _register_ceremony(seed, alg, rp_id, origin, label, uv) -> dict:
	"""Run a REAL registration ceremony for ``frappe.session.user`` with the
	deterministic authenticator: ``begin_registration`` mints a live challenge, the
	fake signs it, ``verify_registration`` persists the row through the unmodified
	verifier. Returns ``{name, credential_id, handle, seed, alg}`` — ``handle`` is the
	server-minted user handle a caller aligns onto the authenticator before login."""
	user = frappe.session.user
	if user in ("Guest", ""):
		frappe.throw("fake_webauthn registration needs an authenticated session user")
	# A full sudo window is the registration gate — stand in for a real re-auth.
	state.set_sudo_window(frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, 600)
	begun = registration.begin_registration(flow="explicit")
	auth = SoftAuthenticator(alg=alg, seed=seed)
	credential = auth.registration(
		challenge_b64=begun["options"]["challenge"],
		rp_id=rp_id,
		origin=origin,
		uv=uv,
		credprops_rk=True,
	)
	result = registration.verify_registration(begun["state_id"], credential, label)
	handle = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
	return {
		"name": result["name"],
		"credential_id": credential["id"],
		"handle": handle,
		"seed": seed,
		"alg": alg,
	}


def _login_ceremony(auth, rp_id: str, origin: str, sign_count: int = 1) -> str:
	"""Drive the REAL first-factor login endpoints without a browser and return the
	resolved session user. ``begin_login`` mints a challenge + the HttpOnly binder
	cookie; the fake signs the challenge; ``verify_login`` matches the binder and mints
	the session. The cookie the browser would carry between the two calls is bridged
	in-process (capture the value ``begin_login`` set, replay it on the verify request)
	— the binder login-CSRF defence is exercised, not bypassed."""
	ip = frappe.generate_hash(length=12)  # per-run rate-limit bucket

	def _request(binder=None):
		headers = [("Cookie", f"{state.BINDER_COOKIE}={binder}")] if binder else None
		set_request(method="POST", path="/api/method/passkeys.passkey.begin_login", headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = ip
		frappe.local.form_dict = frappe._dict()

	_request()
	begun = passkey.begin_login()
	set_cookie = frappe.local.cookie_manager.cookies.get(state.BINDER_COOKIE)
	binder = set_cookie["value"] if set_cookie else None

	assertion = auth.assertion(
		challenge_b64=begun["options"]["challenge"],
		rp_id=rp_id,
		origin=origin,
		sign_count=sign_count,
	)

	_request(binder=binder)
	passkey.verify_login(begun["state_id"], assertion)
	return frappe.session.user
