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
		if self._is_disabling():
			# §8.6 lockout interlock (soft-disable direction): refuse before the write.
			self._guard_last_login_method("disable")

	def on_update(self):
		# §8.6: owner notice when a System Manager soft-disables a credential
		# (disable > delete for forensics). Fires after the write persisted.
		if self._is_disabling():
			self._notify(removed=False)

	def on_trash(self):
		# §8.6 admin/recovery interlock: a System Manager form-delete of the last
		# enabled credential of a passkey-only user (or under disable_user_pass_login)
		# would produce the documented total lockout — refuse with remediation. The
		# User on_trash cascade uses raw ``frappe.db.delete`` (§2.2), which does NOT
		# fire this hook, so deleting a User is never blocked by it.
		if cint(self.enabled):
			self._guard_last_login_method("delete")

	def after_delete(self):
		# §8.3/§8.6: owner notification is sent even when a System Manager removes
		# the row (single source for both the endpoint delete and a form delete).
		self._notify(removed=True)

	def _is_disabling(self) -> bool:
		"""True iff this save flips ``enabled`` 1→0 (§8.6 disable direction)."""
		if self.is_new():
			return False
		before = self.get_doc_before_save()
		was_enabled = (
			cint(before.enabled) if before else cint(frappe.db.get_value(self.doctype, self.name, "enabled"))
		)
		return bool(was_enabled and not cint(self.enabled))

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

	def _guard_admin_disable(self):
		"""§8.6: soft-disabling (enabled 1→0) the last enabled credential of a
		passkey-only user is the same lockout as deleting it — refuse it, and notify
		the owner when a disable does go through."""
		if self.is_new():
			return
		was_enabled = cint(frappe.db.get_value(self.doctype, self.name, "enabled"))
		if not (was_enabled and not cint(self.enabled)):
			return  # not a 1→0 disable transition
		self._guard_last_login_method("disable")
		self._notify(removed=False)

	def _guard_last_login_method(self, action: str):
		"""Refuse removing/disabling the caller's final passkey-capable credential
		when the owner would then have no login method (§8.3/§8.6, census mirroring
		``validate_user_pass_login``)."""
		others = frappe.db.count(self.doctype, {"user": self.user, "enabled": 1, "name": ["!=", self.name]})
		if others > 0:
			return  # another enabled credential survives
		passkey_only = cint(
			frappe.db.get_value("WebAuthn User Handle", {"user": self.user}, "passkey_only_login")
		)
		if passkey_only or frappe.get_system_settings("disable_user_pass_login"):
			frappe.throw(
				_(
					"Cannot {0} the only enabled passkey of {1}: passwordless login is on for that"
					" account, so this would lock them out. Clear 'Passkey Only Login' on their"
					" WebAuthn User Handle first (or ensure another login method), then retry."
				).format(action, self.user),
				frappe.ValidationError,
			)

	def _notify(self, *, removed: bool):
		from passkeys import notifications

		if removed:
			notifications.notify_credential_removed(self.user, self.label or self.name)
		else:
			notifications.notify_credential_disabled(self.user, self.label or self.name)
