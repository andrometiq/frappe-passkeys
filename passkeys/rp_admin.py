# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RP change previews and stale-credential maintenance."""

import frappe
from frappe import _
from frappe.query_builder import Case
from frappe.query_builder.functions import Coalesce, Count, Sum
from frappe.utils import cint

from passkeys import policy
from passkeys.passkeys.doctype.webauthn_credential.webauthn_credential import FlaggedPasskeyKept
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import lock_passkey_modes


def stale_credentials(site_rp_id) -> list:
	return [
		row
		for row in frappe.get_all(
			"WebAuthn Credential", fields=["name", "user", "rp_id", "flagged"], order_by="name"
		)
		if policy.is_stale(row.rp_id, site_rp_id)
	]


def stale_passkey_summary(settings=None) -> dict | None:
	"""Counts for the settings page: one aggregate query, never the rows (hot path).

	Stale matches ``policy.is_stale``; ``rp_id`` is stored normalized at insert."""
	site_rp_id = policy.get_site_rp_id(settings)
	if site_rp_id is None:
		return None
	cred = frappe.qb.DocType("WebAuthn Credential")
	passkeys, users, removable = (
		frappe.qb.from_(cred)
		.select(
			Count("*"),
			Count(cred.user).distinct(),
			Sum(Case().when(Coalesce(cred.flagged, 0) == 0, 1).else_(0)),
		)
		.where(cred.rp_id.isnull() | (cred.rp_id == "") | (cred.rp_id != site_rp_id))
		.run()[0]
	)
	return {
		"site_rp_id": site_rp_id,
		"passkeys": cint(passkeys),
		"users": cint(users),
		"removable": cint(removable),
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
	return {
		"current_rp_id": current,
		"new_rp_id": new,
		"new_off": new is None,
		"stop": _working_transition_counts(current, new),
		"start": _working_transition_counts(new, current),
	}


def _working_transition_counts(working, other) -> dict:
	"""Enabled passkeys that work under ``working`` and are stale under ``other`` (one
	aggregate query; ``policy.is_stale`` is equality with the site RP, None = off)."""
	if working is None:
		return {"passkeys": 0, "users": 0}
	cred = frappe.qb.DocType("WebAuthn Credential")
	condition = (cred.enabled == 1) & (cred.rp_id == working)
	if other is not None:
		condition &= cred.rp_id != other
	passkeys, users = (
		frappe.qb.from_(cred).select(Count("*"), Count(cred.user).distinct()).where(condition).run()[0]
	)
	return {"passkeys": cint(passkeys), "users": cint(users)}


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
