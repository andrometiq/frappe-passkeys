# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted helpers the Cypress login specs (`cypress/integration/*.cy.js`)
call via ``cy.call`` to set up + tear down server state on the shared UI-test
site (DESIGN-v1 §12.3). Mirrors ``frappe/tests/ui_test_helpers.py``: admin-only,
gated to a developer/test bench, never a production surface.

These are the app's **test scaffolding only** — they fold away with the
``shims/`` on the core merge. They set Passkey Settings values **directly**
(``set_single_value``) rather than through ``Passkey Settings.validate``: the
enable-time validator refuses an ``http://`` origin unless developer mode is on,
but the runtime login path (``resolve_origins`` + the library's
``expected_origin`` check) accepts whatever origin list is stored — so a
``*.localhost`` UI-test bench works without threading developer-mode through the
DocType validator. ``webauthn`` is never imported here (§1.3 hook-path
discipline is not at stake, but the parity is cheap)."""

import frappe
from frappe.utils import cint


def _guard() -> None:
	"""Admin-only, developer/test bench only — never callable in production."""
	frappe.only_for("System Manager")
	if not (frappe.conf.get("developer_mode") or getattr(frappe.flags, "in_test", False)):
		frappe.throw("passkeys UI-test helpers require a developer/test bench")


@frappe.whitelist()
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
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.db.commit()
	return values


_2FA_ROLE = "Passkey 2FA UI Role"


@frappe.whitelist()
def configure_second_factor(
	rp_id: str,
	origin: str,
	login_with_passkey: int = 0,
	allow_otp_fallback: int = 0,
) -> dict:
	"""Set up the password → passkey second-factor mode for the P4 Cypress spec
	(DESIGN-v1 §6): turn core Two Factor Authentication ON (the structural floor,
	§6.1), point Passkey Settings at the UI-test origin, and enable
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
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.db.commit()
	return values


@frappe.whitelist()
def teardown_second_factor() -> dict:
	"""Undo :func:`configure_second_factor` (P4 spec ``after``): drop the app
	second-factor mode, then core 2FA. ``set_single_value`` bypasses the
	doc_events guard (which would otherwise block the 1→0 flip), so order is
	immaterial — clear the app knob first for clarity."""
	_guard()
	frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
	frappe.db.set_single_value("Passkey Settings", "passkey_2fa_allow_otp_fallback", 0)
	frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 0)
	frappe.local.system_settings = None
	frappe.clear_document_cache("System Settings", "System Settings")
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.db.commit()
	return {"ok": 1}


@frappe.whitelist()
def ensure_second_factor_user(email: str, pwd: str) -> str:
	"""Get-or-create a NON-admin test user with a known password (the passkey
	second factor is hard-exempt for Administrator, §6.2). Returns the user name."""
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


@frappe.whitelist()
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


@frappe.whitelist()
def delete_test_user(email: str) -> dict:
	"""Remove a user created by :func:`ensure_second_factor_user` (P4 spec cleanup)."""
	_guard()
	frappe.db.delete("WebAuthn Credential", {"user": email})
	frappe.db.delete("WebAuthn User Handle", {"user": email})
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=1, ignore_permissions=True, delete_permanently=True)
	frappe.db.commit()
	return {"ok": 1}


@frappe.whitelist()
def purge_passkeys(user: str) -> dict:
	"""Delete every WebAuthn Credential + User Handle row for ``user`` — DB
	cleanup for ``testIsolation:false`` specs on a shared bench site."""
	_guard()
	deleted = frappe.db.count("WebAuthn Credential", {"user": user})
	frappe.db.delete("WebAuthn Credential", {"user": user})
	frappe.db.delete("WebAuthn User Handle", {"user": user})
	frappe.db.commit()
	return {"deleted": deleted}


@frappe.whitelist()
def make_uv_uninitialized(user: str) -> dict:
	"""Force ``uv_initialized=0`` on the user's credential(s) so a UV=1 assertion
	drives the §3.4 uv-setup step-up (the conditional-create-born state, produced
	server-side without needing a conditional-create browser ceremony)."""
	_guard()
	names = frappe.get_all("WebAuthn Credential", filters={"user": user}, pluck="name")
	for name in names:
		frappe.db.set_value("WebAuthn Credential", name, "uv_initialized", 0, update_modified=False)
	frappe.db.commit()
	return {"updated": names}


@frappe.whitelist()
def credential_count(user: str) -> int:
	"""Server-side truth for a spec's post-condition assertions."""
	_guard()
	return frappe.db.count("WebAuthn Credential", {"user": user})


# ---------------------------------------------------------------------------
# §7 action-confirmation ("passkey signing") probes — the decorated endpoints the
# P5 confirm Cypress specs drive through the frozen `frappe.passkeys.*` client.
# These import `passkeys.confirm` (webauthn-free) and register their actions at
# import time — pure test scaffolding, folds away with the shims on core merge.
# ---------------------------------------------------------------------------

from passkeys.confirm import passkey_protected  # noqa: E402

# Namespaced probe actions (never collide with the app's own passkeys.* actions).
CONFIRM_PROBE_ACTION = "passkeys.tests.confirm_probe"
CONFIRM_PROBE_PASSKEY_ONLY_ACTION = "passkeys.tests.confirm_probe_passkey_only"
CONFIRM_PROBE_FAILING_ACTION = "passkeys.tests.confirm_probe_failing"


@frappe.whitelist(methods=["POST"])
@passkey_protected(action=CONFIRM_PROBE_ACTION, bind_params=["token"], allow_password_fallback=True)
def confirm_probe(token=None) -> dict:
	"""A @passkey_protected endpoint the confirm-happy / call-retry / password-
	fallback / concurrency specs hit: a valid grant for ``(action, {token})`` runs
	it; otherwise it 401s the retry contract. ``allow_password_fallback=True`` so
	the password tab is offered (§7.2)."""
	return {"confirmed": True, "token": token}


@frappe.whitelist(methods=["POST"])
@passkey_protected(
	action=CONFIRM_PROBE_PASSKEY_ONLY_ACTION, bind_params=["token"], allow_password_fallback=False
)
def confirm_probe_passkey_only(token=None) -> dict:
	"""Passkey-only assurance variant (``allow_password_fallback=False``): the
	error-taxonomy spec asserts the dialog offers no password door and a password
	grant never satisfies it."""
	return {"confirmed": True, "token": token}


@frappe.whitelist(methods=["POST"])
@passkey_protected(action=CONFIRM_PROBE_FAILING_ACTION, bind_params=["token"])
def confirm_probe_failing(token=None):
	"""Consumes the grant, then fails — the grant-semantics spec asserts the
	gesture is burned even when the wrapped action fails (A-F20): a retry needs a
	fresh ceremony."""
	frappe.throw("intentional post-consume failure (A-F20 probe)", frappe.ValidationError)
