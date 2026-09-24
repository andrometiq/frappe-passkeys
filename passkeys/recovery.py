# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Operator recovery helpers for lockout situations.

Run from the server console; these are deliberately not whitelisted:
    bench --site <site> execute passkeys.recovery.disable_enforcement
"""

import frappe
from frappe.utils import cint


def disable_enforcement():
	"""Stop requiring a passkey: set scope to ``No one`` and clear the System Manager
	safeguard. Other Passkey Settings, including Everyone else, stay as they are."""
	scope = frappe.db.get_single_value("Passkey Settings", "passkey_enforce_scope") or "No one"
	privileged = cint(frappe.db.get_single_value("Passkey Settings", "passkey_enforce_privileged_always"))
	if scope == "No one" and not privileged:
		print(
			"Passkey enforcement is already disabled "
			"(Require a passkey from: No one; System Managers are not required)."
		)
		return

	frappe.db.set_single_value("Passkey Settings", "passkey_enforce_scope", "No one")
	frappe.db.set_single_value("Passkey Settings", "passkey_enforce_privileged_always", 0)
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.db.commit()  # nosemgrep: frappe-manual-commit
	print(
		"Passkey enforcement disabled: Require a passkey from changed from "
		f"{scope} to No one, and Always require a passkey from System Managers is off."
	)
