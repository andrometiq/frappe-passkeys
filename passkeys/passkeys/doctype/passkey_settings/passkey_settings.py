# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint

from passkeys import policy, state
from passkeys.passkey import refuse_if_core_native
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import (
	lock_passkey_mode_floor,
)


class PasskeySettings(Document):
	def validate(self):
		self._enforce_passkey_only_login_guard()
		if self._any_mode_enabled():
			self._validate_enablement()
		else:
			self._validate_inactive_origins()
		self._validate_reauth_window()
		self._validate_second_factor_floor()
		self._validate_enrollment_policy()
		self._warn_risky_combinations()
		self._warn_enforcement_risks()

	def _any_mode_enabled(self) -> bool:
		return bool(cint(self.login_with_passkey) or cint(self.passkey_as_second_factor))

	def _enforcing(self) -> bool:
		"""True iff the policy is an enforcement rung (``Enforce`` /
		``Enforce After Date``) — regardless of whether the date has arrived yet."""
		return self.passkey_enrollment_policy in ("Enforce", "Enforce After Date")

	def _validate_enrollment_policy(self):
		"""Hard guards on the adoption ladder. ``Enforce After Date`` requires the date;
		grace logins cannot be negative. (The self-lockout / inert-policy heads-ups are
		non-blocking — see ``_warn_enforcement_risks``.)"""
		if self.passkey_enrollment_policy == "Enforce After Date" and not self.passkey_enforce_after:
			frappe.throw(
				_(
					"Enrollment Policy 'Enforce After Date' requires an Enforce After date. Set the date, or choose 'Enforce' to enforce immediately."
				)
			)
		if cint(self.passkey_enforce_grace_logins) < 0:
			frappe.throw(_("Grace Logins cannot be negative. Use 0 to block immediately."))

	def _validate_enablement(self):
		"""Enabling any mode requires an importable webauthn, a resolved
		RP ID, HTTPS origins within the RP ID's scope, and a site encryption key."""
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
					"Cannot enable passkeys: no Relying Party ID resolves. Fix it one of two ways: set host_name in the site config (site_config.json) to this site's domain, or enter an explicit Passkey RP ID (a bare host name) in the Passkey RP ID field."
				)
			)
		policy.validate_origins(self, rp_id)
		policy.validate_app_origins(self)
		if not frappe.conf.get("encryption_key"):
			frappe.throw(
				_(
					"Cannot enable passkeys: this site has no encryption_key. Create the site encryption key before enabling an authentication mode."
				)
			)

	def _validate_inactive_origins(self):
		if self.passkey_origins:
			policy.validate_origins(self, policy.resolve_rp_id(self))
		if self.passkey_app_origins:
			policy.validate_app_origins(self)

	def _validate_reauth_window(self):
		if cint(self.passkey_reauth_window) < 0:
			frappe.throw(_("Re-auth Window cannot be negative."), frappe.ValidationError)

	def _validate_second_factor_floor(self):
		"""The enforcement floor is structural — passkey second factor
		requires core two-factor auth to stay ON (direct password POSTs then
		face core's own OTP gate on every branch, with zero hook dependence)."""
		if not cint(self.passkey_as_second_factor):
			return
		if not cint(self.login_with_passkey) and cint(
			frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		):
			frappe.throw(
				_(
					"Passkey as Second Factor cannot be the only passkey mode while username/password login is disabled. Enable Login with Passkey or re-enable username/password login."
				),
				frappe.ValidationError,
			)
		if not policy.lock_core_2fa_floor():
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
		"""Generalized disable-guard: no save may leave zero
		passkey-capable login modes while any user has passkey_only_login=1."""
		lock_passkey_mode_floor()
		if self._any_mode_enabled():
			return
		flagged = frappe.db.get_values(
			"WebAuthn User Handle",
			{"passkey_only_login": 1},
			"user",
			order_by=None,
			for_update=True,
			pluck=True,
		)
		if flagged:
			frappe.throw(
				_(
					"Cannot save: this would leave no passkey-capable login mode enabled while these users allow passkey login only: {0}. Keep a passkey login mode enabled, or clear 'Passkey Only Login' on their WebAuthn User Handle records first."
				).format(", ".join(flagged))
			)

	def _warn_risky_combinations(self):
		# non-blocking warnings — the save proceeds
		if cint(self.passkey_as_second_factor) and cint(
			frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		):
			frappe.msgprint(
				_(
					"Passkey as Second Factor is unusable for enrolled users while username/password login is disabled: the app's password leg cannot start, and alternate login completions are final-vetoed. Keep Login with Passkey enabled as their usable route."
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

	def _warn_enforcement_risks(self):
		"""Non-blocking heads-ups for the enforcement rungs (the save proceeds). Mirror
		the enrollment-policy banner matrix in ``passkey_manage_common.bundle.js``."""
		if not self._enforcing():
			return
		# Enforcement is inert without a passkey login mode — nothing to require.
		if not self._any_mode_enabled():
			frappe.msgprint(
				_(
					"Enrollment enforcement has no effect while both passkey login modes are off — enable 'Login with Passkey' or 'Passkey as Second Factor' for the policy to apply."
				),
				indicator="orange",
			)
		# Self-lockout risk: enforcing everyone without System Manager exempt.
		exempt_roles = {row.role for row in (self.passkey_enforce_exempt_roles or [])}
		if self.passkey_enforce_scope != "Selected Roles" and "System Manager" not in exempt_roles:
			frappe.msgprint(
				_(
					"System Manager is not in the exempt roles while enforcing for all users — an administrator on a device that cannot create a passkey could be locked out. Keep System Manager exempt as a break-glass unless you are certain."
				),
				indicator="orange",
			)
		# Selected-roles scope with no roles listed enforces against nobody.
		if self.passkey_enforce_scope == "Selected Roles" and not (self.passkey_enforce_roles or []):
			frappe.msgprint(
				_(
					"Enforcement scope is 'Selected Roles' but no roles are listed, so the policy applies to nobody. Add the roles you want to enforce, or switch the scope to 'All Users'."
				),
				indicator="orange",
			)
		# Block + Notify can hard-lock genuinely incapable devices.
		if self.passkey_enforce_incapable == "Block + Notify Admin":
			frappe.msgprint(
				_(
					"Incapable Device Policy is 'Block + Notify Admin': users on devices that cannot create a passkey (and cannot use a phone) will be blocked rather than nudged. Prefer 'Degrade to Nudge' if any users may be on older devices."
				),
				indicator="orange",
			)


@frappe.whitelist(methods=["POST"])
def get_resolved_rp_id() -> dict:
	"""Return the RP ID the SERVER will actually resolve right now, so the Passkey
	Settings form can display server-truth instead of guessing from the browser host
	(``window.location.hostname`` never matches an RP ID that comes from ``host_name``,
	which is exactly the A1 confusion: the form showed a value Save then rejected).

	Read-only and System-Manager-gated (the settings form is admin-only). Follows the
	app endpoint idioms: ``refuse_if_core_native`` first (dormant-shell 417) and a
	per-user rate limit."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	frappe.only_for("System Manager")
	state.rate_limit_user("get_resolved_rp_id", 30, 60)  # 30/min/user
	settings = frappe.get_cached_doc("Passkey Settings")
	rp_id = policy.resolve_rp_id(settings)
	return {
		"rp_id": rp_id,
		"configured_site_origin": policy.resolve_site_origin(rp_id or ""),
		"host_name_configured": bool((frappe.conf.get("host_name") or "").strip()),
	}


@frappe.whitelist(methods=["POST"])
def get_security_posture() -> dict:
	"""Return the admin security-posture verdict for the Passkey Settings page: given
	the site's ACTUAL auth surface (password / email-link / social / LDAP sign-in + the
	core second factor) and this app's own state, can a passkey still be bypassed, and
	how to close each gap.

	Read-only and System-Manager-gated (the settings form is admin-only), so — unlike
	guest login copy — the rows are deliberately concrete about the exact setting to
	change. Follows the app endpoint idioms: ``refuse_if_core_native`` first (dormant
	417) and a per-user rate limit."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	frappe.only_for("System Manager")
	state.rate_limit_user("get_security_posture", 30, 60)  # 30/min/user
	from passkeys import posture

	return posture.build_posture()
