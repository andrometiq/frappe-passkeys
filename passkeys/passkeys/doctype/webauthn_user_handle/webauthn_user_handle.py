# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint


class WebAuthnUserHandle(Document):
	def validate(self):
		self._enforce_immutable_identity()
		self._enforce_credential_floor()

	def _enforce_immutable_identity(self):
		if self.is_new():
			return
		before = self._previous_values()
		if self.user != before.user:
			frappe.throw(_("The user of a WebAuthn User Handle can never change."))
		if self.handle != before.handle:
			frappe.throw(_("A WebAuthn user handle is immutable."))

	def _enforce_credential_floor(self):
		"""§2.2: enabling passkey-only login requires ≥1 enabled credential.
		This binds every writer (endpoint, Desk form, System Manager) — without
		it, a toggle on a credential-less user is an instant total lockout."""
		if not cint(self.passkey_only_login):
			return
		if not self.is_new() and cint(self._previous_values().passkey_only_login):
			return
		if not frappe.db.exists("WebAuthn Credential", {"user": self.user, "enabled": 1}):
			frappe.throw(
				_("Passkey-only login requires at least one enabled passkey for user {0}.").format(self.user)
			)

	def _previous_values(self):
		before = self.get_doc_before_save()
		if before:
			return before
		values = frappe.db.get_value(
			self.doctype, self.name, ["user", "handle", "passkey_only_login"], as_dict=True
		)
		return values or frappe._dict()
