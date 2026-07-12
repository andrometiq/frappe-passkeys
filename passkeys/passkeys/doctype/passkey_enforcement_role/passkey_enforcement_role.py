# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

from frappe.model.document import Document


class PasskeyEnforcementRole(Document):
	"""Child row holding a single Role for the Passkey Settings enforcement
	scope / exempt Table MultiSelects. The ``parentfield`` distinguishes the two
	uses (``passkey_enforce_roles`` vs ``passkey_enforce_exempt_roles``)."""

	pass
