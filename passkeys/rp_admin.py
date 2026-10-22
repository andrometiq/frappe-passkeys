# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RP change previews and stale-credential maintenance."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import policy
from passkeys.passkeys.doctype.webauthn_credential.webauthn_credential import FlaggedPasskeyKept
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import lock_passkey_modes


def credential_counts(rows) -> dict:
	return {"passkeys": len(rows), "users": len({row.user for row in rows})}


def stale_credentials(site_rp_id) -> list:
	return [
		row
		for row in frappe.get_all(
			"WebAuthn Credential", fields=["name", "user", "rp_id", "flagged"], order_by="name"
		)
		if policy.is_stale(row.rp_id, site_rp_id)
	]


def stale_passkey_summary(settings=None) -> dict | None:
	site_rp_id = policy.get_site_rp_id(settings)
	if site_rp_id is None:
		return None
	rows = stale_credentials(site_rp_id)
	return {
		"site_rp_id": site_rp_id,
		**credential_counts(rows),
		"removable": sum(not cint(row.flagged) for row in rows),
	}


def rp_id_change_impact(rp_id, passkey_origins=None, passkey_app_origins=None) -> dict:
	settings = policy.read_rp_settings()
	candidate = {**settings, "passkey_rp_id": rp_id}
	for field, value in (("passkey_origins", passkey_origins), ("passkey_app_origins", passkey_app_origins)):
		if value is not None:
			candidate[field] = value
	resolved = policy.resolve_rp_id(candidate)
	for line in (candidate.get("passkey_origins") or "").splitlines():
		if line.strip() and (error := policy.origin_error(line.strip(), resolved)):
			frappe.throw(error, frappe.ValidationError)
	policy.validate_app_origins(candidate)
	current = policy.get_site_rp_id(settings)
	new = policy.get_site_rp_id(candidate)
	rows = frappe.get_all("WebAuthn Credential", filters={"enabled": 1}, fields=["user", "rp_id"])
	return {
		"current_rp_id": current,
		"new_rp_id": new,
		"new_off": new is None,
		"stop": credential_counts(
			[
				row
				for row in rows
				if not policy.is_stale(row.rp_id, current) and policy.is_stale(row.rp_id, new)
			]
		),
		"start": credential_counts(
			[
				row
				for row in rows
				if policy.is_stale(row.rp_id, current) and not policy.is_stale(row.rp_id, new)
			]
		),
	}


def remove_stale_passkeys(site_rp_id) -> dict:
	current = policy.get_site_rp_id(lock_passkey_modes())
	if current is None:
		frappe.throw(
			_("Passkeys are off on this site, so every passkey would look stale. Fix the RP ID first.")
		)
	if current != site_rp_id:
		frappe.throw(_("The RP ID changed since this page loaded. Reload and try again."))
	removed = 0
	for row in stale_credentials(current):
		if cint(row.flagged):
			continue
		try:
			frappe.delete_doc(
				"WebAuthn Credential", row.name, ignore_missing=False, flags={"passkeys_remove_stale": True}
			)
		except FlaggedPasskeyKept:
			continue
		except frappe.DoesNotExistError as exc:
			if exc.doctype != "WebAuthn Credential":
				raise
			continue  # An ordinary owner delete may have won while this request waited.
		removed += 1
	return {"removed": removed}
