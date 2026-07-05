# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint, strip_html

LABEL_MAX_LENGTH = 140


class WebAuthnCredential(Document):
	def validate(self):
		self._sanitize_label()
		self._enforce_write_once_invariants()

	def _sanitize_label(self):
		# server-side length-cap + sanitize (stored-XSS class; §2.1)
		if self.label:
			self.label = strip_html(self.label).strip()[:LABEL_MAX_LENGTH]

	def _enforce_write_once_invariants(self):
		if self.is_new():
			return
		before = self.get_doc_before_save()
		if not before:
			before = frappe._dict(
				zip(
					("backup_eligible", "sign_count"),
					frappe.db.get_value(self.doctype, self.name, ["backup_eligible", "sign_count"]),
					strict=False,
				)
			)
		if cint(self.backup_eligible) != cint(before.backup_eligible):
			frappe.throw(_("Backup eligibility is set at registration and can never change."))
		if cint(self.sign_count) < cint(before.sign_count):
			frappe.throw(_("The signature counter is never written downward."))
