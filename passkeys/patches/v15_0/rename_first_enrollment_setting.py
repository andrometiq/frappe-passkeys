# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe

OLD = "passkey_allow_first_enrollment_on_weak_login"
NEW = "passkey_allow_first_enrollment_on_external_login"


def execute():
	"""Carry the site's choice over to the renamed Passkey Settings field; it replaces any
	value already stored under the new name (the synced default)."""
	rows = frappe.db.sql(
		"select value from `tabSingles` where doctype=%s and field=%s",
		("Passkey Settings", OLD),
	)
	if not rows:
		return
	frappe.db.set_single_value("Passkey Settings", NEW, rows[0][0])
	frappe.db.sql(
		"delete from `tabSingles` where doctype=%s and field=%s",
		("Passkey Settings", OLD),
	)
	frappe.clear_cache(doctype="Passkey Settings")
