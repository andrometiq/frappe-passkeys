# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Remove orphaned role-wide enforcement exemptions from upgraded sites."""

import frappe

from passkeys import install


def execute():
	if install.is_core_native():
		return  # dormant shell: core owns Passkey Settings — nothing to migrate

	frappe.db.delete(
		"Passkey Enforcement Role",
		{
			"parent": "Passkey Settings",
			"parentfield": "passkey_enforce_exempt_roles",
		},
	)
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
