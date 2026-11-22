# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint, strip_html

from passkeys import policy
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import lock_login_floor
from passkeys.session import ReadOnlyWhileImpersonated

LABEL_MAX_LENGTH = 140


class FlaggedPasskeyKept(frappe.ValidationError):
	pass


class WebAuthnCredential(ReadOnlyWhileImpersonated, Document):
	def validate(self):
		super().validate()
		if self.is_new():
			self.rp_id = policy.normalize_rp_id(self.rp_id)
		self._sanitize_label()
		self._enforce_write_once_invariants()
		if self._is_disabling():
			# lockout interlock (soft-disable direction): refuse before the write.
			self._guard_last_login_method("disable")

	def on_update(self):
		# A disable (preferred to a delete, for forensics) ends the owner's sessions, then tells
		# the owner. Fires after the write persisted.
		if self._is_disabling():
			self._notify(removed=False, is_signed_out=self._sign_out_owner())

	def on_trash(self):
		super().on_trash()
		# admin/recovery interlock: a System Manager form-delete of the last
		# enabled credential of a passkey-only user (or under disable_user_pass_login)
		# would produce the documented total lockout — refuse with remediation. The
		# guard decides on fresh, locked reads (never this transaction's snapshot)
		# whether the row still counts as an enabled credential. The User on_trash
		# cascade uses raw ``frappe.db.delete``, which does NOT fire this hook, so
		# deleting a User is never blocked by it.
		self._guard_last_login_method("delete")
		# delete_doc may load a removed row from its earlier repeatable-read snapshot.
		current = frappe.db.get_value(
			self.doctype, self.name, ["name", "flagged"], as_dict=True, for_update=True
		)
		if not current:
			raise frappe.DoesNotExistError(doctype=self.doctype)
		if self.flags.passkeys_remove_stale and cint(current.flagged):
			raise FlaggedPasskeyKept

	def after_delete(self):
		# Single source for the endpoint delete and a form delete.
		self._notify(removed=True, is_signed_out=self._sign_out_owner())

	def _is_disabling(self) -> bool:
		"""True iff this save flips ``enabled`` 1→0 (disable direction)."""
		if self.is_new():
			return False
		before = self.get_doc_before_save()
		was_enabled = (
			cint(before.enabled) if before else cint(frappe.db.get_value(self.doctype, self.name, "enabled"))
		)
		return bool(was_enabled and not cint(self.enabled))

	def _sanitize_label(self):
		# server-side length-cap + sanitize (stored-XSS class)
		if self.label:
			self.label = strip_html(self.label).strip()[:LABEL_MAX_LENGTH]

	def _enforce_write_once_invariants(self):
		if self.is_new():
			return
		before = self.get_doc_before_save()
		if not before:
			before = frappe.db.get_value(
				self.doctype,
				self.name,
				[
					"rp_id",
					"user",
					"credential_id",
					"credential_id_sha256",
					"public_key",
					"backup_eligible",
					"sign_count",
				],
				as_dict=True,
			)
		if self.rp_id != before.rp_id:
			frappe.throw(_("The RP ID of a WebAuthn Credential can never change."))
		if self.user != before.user:
			frappe.throw(_("The user of a WebAuthn Credential can never change."))
		if self.credential_id != before.credential_id:
			frappe.throw(_("A WebAuthn credential ID is immutable."))
		if self.credential_id_sha256 != before.credential_id_sha256:
			frappe.throw(_("A WebAuthn credential ID digest is immutable."))
		if self.public_key != before.public_key:
			frappe.throw(_("A WebAuthn credential public key is immutable."))
		if cint(self.backup_eligible) != cint(before.backup_eligible):
			frappe.throw(_("Backup eligibility is set at registration and can never change."))
		if cint(self.sign_count) < cint(before.sign_count):
			frappe.throw(_("The signature counter is never written downward."))

	def _guard_last_login_method(self, action: str):
		"""Refuse removing/disabling the caller's final passkey-capable credential
		when the owner would then have no login method (census mirroring
		``validate_user_pass_login``). Serialized: every writer of the lockout
		invariant queues on the owner's handle row and re-checks against locking
		reads — a plain count re-reads the REPEATABLE READ snapshot even after the
		lock, which is what let two overlapping removals each see a survivor and
		drop every credential of a passkey-only user."""
		passkey_only, usable_names = lock_login_floor(self.user)
		if any(name != self.name for name in usable_names):
			return  # another enabled credential survives
		if self.name not in usable_names:
			return  # not an enabled credential (fresh, under lock) — dropping it removes no login method
		if passkey_only or frappe.get_system_settings("disable_user_pass_login"):
			frappe.throw(
				_(
					"Cannot {0} the only enabled passkey of {1}: passwordless login is on for that"
					" account, so this would lock them out. Clear 'Passkey Only Login' on their"
					" WebAuthn User Handle first (or ensure another login method), then retry."
				).format(action, self.user)
				if passkey_only
				else _(
					"Cannot {0} the only enabled passkey of {1}: Disable Username/Password Login is on "
					"in System Settings. Add another enabled passkey or turn off Disable Username/Password Login "
					"in System Settings, then retry."
				).format(action, self.user),
				frappe.ValidationError,
			)

	def _sign_out_owner(self) -> bool:
		"""End the owner's sessions with core's call for a disabled User: all of them when someone
		else revoked this passkey (the actor's sessions belong to another user and stay), all but
		the current one when the owner did, so a lost device's session ends too. The stale-passkey
		bulk removal is left out: a stale passkey cannot sign in here, and the commits would
		release the RP lock that removal holds. Returns whether the owner was signed out
		everywhere."""
		if self.flags.passkeys_remove_stale:
			return False
		from frappe.sessions import clear_sessions

		by_owner = self._is_by_owner()
		# A fresh snapshot: a sign-in that committed while this request waited on the row lock
		# is listed too; any later one reads the revoked row and fails.
		frappe.db.commit()
		clear_sessions(user=self.user, keep_current=by_owner, force=True)
		return not by_owner

	def _is_by_owner(self) -> bool:
		return frappe.session.user == self.user

	def _notify(self, *, removed: bool, is_signed_out: bool):
		from passkeys import notifications

		label = self.label or self.name
		if removed:
			notifications.notify_credential_removed(
				self.user, label, by_owner=self._is_by_owner(), is_signed_out=is_signed_out
			)
		else:
			notifications.notify_credential_disabled(self.user, label, is_signed_out=is_signed_out)
