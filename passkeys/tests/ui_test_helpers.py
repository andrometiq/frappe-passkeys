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
