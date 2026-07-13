# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint


def lock_login_floor(user: str) -> tuple[int, list[str]]:
	"""Serialize every writer of the lockout invariant — ``passkey_only_login = 1
	⇒ ≥1 enabled credential`` — and return both of its sides, freshly read under
	lock: ``(passkey_only_login, enabled credential names)``.

	Locks the user's ``WebAuthn User Handle`` row (``FOR UPDATE``): the single
	lock object shared by credential delete/disable and the flag toggle, so
	overlapping writers queue instead of racing. The credential census is then a
	**locking** read too, because under InnoDB REPEATABLE READ a plain
	``frappe.db.count`` keeps returning the transaction's snapshot even after the
	lock is acquired — exactly the race that let two overlapping deletes each see
	the other credential survive, pass both guards, and lock a passkey-only user
	out. Registration seeds the handle row before the first credential ever
	inserts, so credential owners always have a row to lock; should it be missing
	anyway, the flag reads 0 and the credential row locks still serialize
	credential-vs-credential writers.
	"""
	flag = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login", for_update=True)
	names = frappe.db.get_values(
		"WebAuthn Credential",
		{"user": user, "enabled": 1},
		"name",
		order_by=None,
		for_update=True,
		pluck=True,
	)
	return cint(flag), list(names or [])


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
		"""Enabling passkey-only login requires ≥1 enabled credential.
		This binds every writer (endpoint, Desk form, System Manager) — without
		it, a toggle on a credential-less user is an instant total lockout. The
		census is read under the invariant lock: a snapshot ``exists`` could miss
		a concurrent delete's commit and re-open the lockout race from the flag
		side."""
		if not cint(self.passkey_only_login):
			return
		if not self.is_new() and cint(self._previous_values().passkey_only_login):
			return
		if not lock_login_floor(self.user)[1]:
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
