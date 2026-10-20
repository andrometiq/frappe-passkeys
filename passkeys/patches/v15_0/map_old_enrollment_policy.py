# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe

from passkeys import boot

DOCTYPE = "Passkey Settings"
SCOPES = {"All Users": "All users", "Selected Roles": "Selected roles"}


def execute():
	"""Carry the old enrollment settings over to "Require a passkey from" / "Everyone else".

	Before 15.0.0 the old scope was stored as "All Users" (its default) even when nobody was
	enforced, because a separate policy (Off / Nudge / Enforce / Enforce After Date) decided
	that. The value is no longer a valid option, so the form shows the field blank and refuses
	to save. Only an old Enforce policy keeps its scope; everything else becomes "No one", so
	the upgrade never starts requiring passkeys on its own."""
	stored = dict(
		frappe.db.sql(
			"select field, value from `tabSingles` where doctype=%s and field in %s",
			(DOCTYPE, ("passkey_enrollment_policy", "passkey_enforce_scope")),
		)
	)
	scope = stored.get("passkey_enforce_scope")
	if scope not in SCOPES:
		return
	policy = stored.get("passkey_enrollment_policy")
	enforced = policy in ("Enforce", "Enforce After Date")
	frappe.db.set_single_value(DOCTYPE, "passkey_enforce_scope", SCOPES[scope] if enforced else "No one")
	if not enforced:
		frappe.db.set_single_value(DOCTYPE, "passkey_enforce_privileged_always", 0)
	for (user,) in frappe.db.sql(
		"select distinct parent from `tabHas Role` where parenttype=%s and role=%s",
		("User", "Passkey Enforcement Exempt"),
	):
		boot.set_exempt(user, True)
	if policy == "Enforce":  # the old policy ignored the date; a leftover one would delay it now
		frappe.db.set_single_value(DOCTYPE, "passkey_enforce_after", None)
	if policy == "Off":
		frappe.db.set_single_value(DOCTYPE, "passkey_everyone_else", "Off")
	frappe.db.sql(
		"delete from `tabSingles` where doctype=%s and field in %s",
		(DOCTYPE, ("passkey_enrollment_policy", "passkey_enforce_allow_hybrid")),
	)
	frappe.clear_cache(doctype=DOCTYPE)
