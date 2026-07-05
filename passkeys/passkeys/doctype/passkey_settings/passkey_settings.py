# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint

from passkeys import policy


class PasskeySettings(Document):
	def validate(self):
		if self._any_mode_enabled():
			self._validate_enablement()
		self._validate_second_factor_floor()
		self._enforce_passkey_only_login_guard()
		self._warn_risky_combinations()

	def _any_mode_enabled(self) -> bool:
		return bool(cint(self.login_with_passkey) or cint(self.passkey_as_second_factor))

	def _validate_enablement(self):
		"""§2.3: enabling any mode requires an importable webauthn, a resolved
		RP ID, and HTTPS origins within the RP ID's scope (§9.2)."""
		if not policy.webauthn_available():
			frappe.throw(
				_(
					"Cannot enable passkeys: the 'webauthn' python package is not installed in this bench. Run bench setup requirements for the passkeys app first."
				)
			)
		rp_id = policy.resolve_rp_id(self)
		if not rp_id:
			frappe.throw(
				_(
					"Cannot enable passkeys: no Relying Party ID resolves. Set Passkey RP ID, or configure host_name in site config."
				)
			)
		policy.validate_origins(self, rp_id)

	def _validate_second_factor_floor(self):
		"""§6.1: the enforcement floor is structural — passkey second factor
		requires core two-factor auth to stay ON (direct password POSTs then
		face core's own OTP gate on every branch, with zero hook dependence)."""
		if not cint(self.passkey_as_second_factor):
			return
		if not cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth")):
			frappe.throw(
				_(
					"Passkey as Second Factor requires Two Factor Authentication to be enabled in System Settings — it is the backstop for password logins that bypass the passkey UI."
				)
			)
		if not frappe.db.exists("Role", {"two_factor_auth": 1, "disabled": 0}):
			frappe.msgprint(
				_(
					"No role has Two Factor Authentication enabled, so the two-factor backstop covers nobody. Consider enabling it for role 'All' in the Role list."
				),
				indicator="orange",
			)

	def _enforce_passkey_only_login_guard(self):
		"""§2.3 generalized disable-guard (pass-3 F3-3): no save may leave zero
		passkey-capable login modes while any user has passkey_only_login=1."""
		if self._any_mode_enabled():
			return
		flagged = frappe.get_all("WebAuthn User Handle", filters={"passkey_only_login": 1}, pluck="user")
		if flagged:
			frappe.throw(
				_(
					"Cannot save: this would leave no passkey-capable login mode enabled while these users allow passkey login only: {0}. Keep a passkey login mode enabled, or clear 'Passkey Only Login' on their WebAuthn User Handle records first."
				).format(", ".join(flagged))
			)

	def _warn_risky_combinations(self):
		# non-blocking warnings (§2.3) — the save proceeds
		if cint(self.passkey_as_second_factor) and cint(
			frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		):
			frappe.msgprint(
				_(
					"Passkey as Second Factor is a dead combination with 'Disable Username/Password Login': the password leg refuses while username/password login is disabled."
				),
				indicator="orange",
			)
		if self._any_mode_enabled() and not cint(self.passkey_notify_on_change):
			frappe.msgprint(
				_(
					"Passkey change notifications are off. They are the compensating control for credential registration hijack — leave them on outside mail-less development sites."
				),
				indicator="orange",
			)
