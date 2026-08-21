# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin enrollment-enforcement recovery endpoints (folds into ``frappe/passkey.py`` on
the core merge).

The three System-Manager-only affordances surfaced on the User form's Passkeys section
for an administrator unblocking a stuck user:

  * **one-click per-user exemption** — mechanism stays role-based: a dedicated role,
    :data:`EXEMPT_ROLE`, created LAZILY on the first exemption (never at install), kept in
    the Passkey Settings exempt-roles table, and assigned/removed on the user. Un-exempt
    removes only the assignment; the role + settings row stay in place.
  * **grace-counter reset** — clears exactly the ``{user}_passkey_enforce`` grace blob
    (see :func:`passkeys.boot.clear_enforcement_state`).
  * a read view-model (:func:`admin_enforcement_view`) the section paints.

Every write endpoint is ``refuse_if_core_native`` (dormant-shell 417) → ``only_for("System
Manager")`` → per-user rate-limited, mirroring the app's other admin endpoints
(``passkey_settings.get_security_posture``)."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import boot, state
from passkeys.passkey import refuse_if_core_native

# The dedicated role that marks a user exempt from passkey enrollment enforcement.
# Created lazily on the first exemption (documented in docs/configuration.md's stuck-user
# runbook), NOT at install time — a site that never grants an exemption never grows it.
EXEMPT_ROLE = "Passkey Enforcement Exempt"

_ENFORCING_POLICIES = ("Enforce", "Enforce After Date")


def _coerce_bool(value) -> bool:
	"""Accept JSON booleans and documented boolean form values only."""
	if isinstance(value, bool):
		return value
	if type(value) is int and value in (0, 1):
		return bool(value)
	if isinstance(value, str):
		normalized = value.strip().lower()
		if normalized in ("1", "true", "yes", "on"):
			return True
		if normalized in ("0", "false", "no", "off"):
			return False
	frappe.throw(_("Exempt must be true or false."), frappe.ValidationError)


def _require_user(user: str) -> str:
	user = (user or "").strip()
	if not user or not frappe.db.exists("User", user):
		frappe.throw(_("No such user: {0}").format(user or _("(empty)")))
	return user


def _ensure_exempt_role() -> None:
	"""Lazily create :data:`EXEMPT_ROLE` and ensure it sits in the Passkey Settings
	exempt-roles table. Idempotent — safe to call on every exemption. The role carries no
	desk access (``desk_access = 0``): it is a pure enforcement marker and grants no
	privilege, so assigning it can never widen a user's access."""
	if not frappe.db.exists("Role", EXEMPT_ROLE):
		role = frappe.new_doc("Role")
		role.role_name = EXEMPT_ROLE
		role.desk_access = 0
		role.flags.ignore_permissions = True
		role.insert()
	settings = frappe.get_doc("Passkey Settings")
	if EXEMPT_ROLE in {row.role for row in (settings.passkey_enforce_exempt_roles or [])}:
		return
	settings.append("passkey_enforce_exempt_roles", {"role": EXEMPT_ROLE})
	settings.flags.ignore_permissions = True
	settings.flags.ignore_mandatory = True
	settings.save()  # clears the Passkey Settings document cache so the next read is fresh


def admin_enforcement_view(user: str) -> dict:
	"""The per-user enforcement admin view-model the User-form Passkeys section paints.

	Reports the user's exemption state — separately via the dedicated role (``exempt``,
	the toggle target) and via ANY OTHER exempt role (``exempt_via_other_role``, e.g. a
	System Manager) — their grace-budget usage, and whether they are currently in
	enforcement scope. Read-only (no mutation), so it is safe to call before and after a
	write to hand the client the refreshed state."""
	settings = frappe.get_cached_doc("Passkey Settings")
	credential_count = frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})
	verdict = boot.build_enforcement(user, settings, credential_count)
	roles = set(frappe.get_roles(user))
	exempt_roles = {row.role for row in (settings.passkey_enforce_exempt_roles or [])}
	return {
		"user": user,
		"policy": verdict["policy"],
		"effective": verdict["effective"],
		"enforcing": settings.passkey_enrollment_policy in _ENFORCING_POLICIES,
		"in_scope": verdict["in_scope"],
		"exempt": EXEMPT_ROLE in roles,
		"exempt_via_other_role": bool(roles & (exempt_roles - {EXEMPT_ROLE})),
		"grace_used": cint(boot.get_enforcement_state(user)["grace_used"]),
		"grace_total": cint(verdict["grace_total"]),
		"grace_remaining": cint(verdict["grace_remaining"]),
		"credential_count": cint(credential_count),
	}


@frappe.whitelist(methods=["POST"])
def get_user_enforcement_admin(user: str) -> dict:
	"""Read the per-user enforcement admin view-model (exemption + grace state). System-
	Manager-only + rate-limited; dormant-shell 417 the moment core serves passkeys."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	frappe.only_for("System Manager")
	state.rate_limit_user("get_user_enforcement_admin", 60, 60)  # 60/min/user
	return admin_enforcement_view(_require_user(user))


@frappe.whitelist(methods=["POST"])
def set_user_exemption(user: str, exempt) -> dict:
	"""Exempt / un-exempt ONE user from passkey enrollment enforcement, via the dedicated
	role. Idempotent (double-click safe): on exempt, lazily create the role, ensure it is
	in the settings exempt table, and assign it to the user (no duplicate Has Role row); on
	un-exempt, remove ONLY the role assignment from the user — the role + settings row stay
	in place. System-Manager-only + rate-limited. Returns the refreshed admin view-model
	(``exempt`` / ``in_scope`` reflect the change)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	frappe.only_for("System Manager")
	state.rate_limit_user("set_user_exemption", 30, 3600)  # 30/hr/user
	user = _require_user(user)
	user_doc = frappe.get_doc("User", user)
	has_role = EXEMPT_ROLE in set(frappe.get_roles(user))
	if _coerce_bool(exempt):
		_ensure_exempt_role()
		if not has_role:
			user_doc.add_roles(EXEMPT_ROLE)  # add_roles is itself idempotent; guard avoids a needless save
	elif has_role:
		user_doc.remove_roles(EXEMPT_ROLE)
	return admin_enforcement_view(user)


@frappe.whitelist(methods=["POST"])
def reset_enforcement_grace(user: str) -> dict:
	"""Clear one user's enforcement grace counter so their full deferral budget is restored
	(``build_enforcement`` then reads a fresh zero-state). Clears EXACTLY the key
	``record_enforcement`` writes and ``build_enforcement`` reads — no parallel state.
	System-Manager-only + rate-limited. Returns the refreshed admin view-model with
	``grace_remaining`` back at ``grace_total``."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	frappe.only_for("System Manager")
	state.rate_limit_user("reset_enforcement_grace", 30, 3600)  # 30/hr/user
	user = _require_user(user)
	boot.clear_enforcement_state(user)
	return admin_enforcement_view(user)
