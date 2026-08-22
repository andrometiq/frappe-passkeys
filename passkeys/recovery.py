# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Operator recovery helpers for lockout situations.

Run from the server console; these are deliberately not whitelisted:
    bench --site <site> execute passkeys.recovery.disable_enforcement
"""

import frappe


def disable_enforcement():
	"""Drop the enrollment policy to Nudge so enforcement stops gating logins."""
	policy = frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy")
	if policy in ("Off", "Nudge"):
		print(f"Passkey enforcement is already disabled (Enrollment Policy: {policy}).")
		return policy

	frappe.db.set_single_value("Passkey Settings", "passkey_enrollment_policy", "Nudge")
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.db.commit()
	print(f"Passkey enforcement disabled: Enrollment Policy changed from {policy or '(unset)'} to Nudge.")
	return "Nudge"
