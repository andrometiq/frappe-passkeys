# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

from frappe.model.document import Document

from passkeys.session import ReadOnlyWhileImpersonated


class PasskeyEnforcementRole(ReadOnlyWhileImpersonated, Document):
	"""Child row holding one selected enforcement-scope role. A standalone row write
	(``frappe.client.save`` of the row, a REST delete) runs the row's own hooks, not the
	parent's ``validate``, so the row carries the impersonation guard itself."""
