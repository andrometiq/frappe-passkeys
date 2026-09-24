# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""System-Manager-only enforcement recovery endpoints for the User form's Passkeys
section: a per-user exemption (the :data:`EXEMPT_ROLE` marker role, created on first use
and never removed), a grace-counter reset, and the section's read view-model. Folds into
``frappe/passkey.py`` on the core merge."""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import boot, state
from passkeys.boot import EXEMPT_ROLE
from passkeys.errors import refuse_if_core_native

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
	"""Create :data:`EXEMPT_ROLE` if missing: a pure marker with no desk access, so
	assigning it never widens a user's access."""
	if not frappe.db.exists("Role", EXEMPT_ROLE):
		role = frappe.new_doc("Role")
		role.role_name = EXEMPT_ROLE
		role.desk_access = 0
		role.flags.ignore_permissions = True
		role.insert()


def admin_enforcement_view(user: str) -> dict:
	"""The user's exemption, grace usage and enforcement scope, as the section paints it."""
	settings = frappe.get_cached_doc("Passkey Settings")
	credential_count = frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})
	verdict = boot.build_enforcement(user, settings, credential_count)
	roles = set(frappe.get_roles(user))
	return {
		"user": user,
		"policy": verdict["policy"],
		"effective": verdict["effective"],
		"enforcing": settings.passkey_enrollment_policy in _ENFORCING_POLICIES,
		"in_scope": verdict["in_scope"],
		"exempt": EXEMPT_ROLE in roles,
		"grace_used": cint(boot.get_enforcement_state(user)["grace_used"]),
		"grace_total": cint(verdict["grace_total"]),
		"grace_remaining": cint(verdict["grace_remaining"]),
		"credential_count": cint(credential_count),
	}


@frappe.whitelist(methods=["POST"])
def get_user_enforcement_admin(user: str) -> dict:
	"""The per-user enforcement admin view-model."""
	refuse_if_core_native()
	frappe.only_for("System Manager")
	state.rate_limit_user("get_user_enforcement_admin", 60, 60)
	return admin_enforcement_view(_require_user(user))


@frappe.whitelist(methods=["POST"])
def set_user_exemption(user: str, exempt: object) -> dict:
	"""Exempt or un-exempt one user by assigning or removing the marker role; idempotent.
	Returns the refreshed view-model."""
	refuse_if_core_native()
	frappe.only_for("System Manager")
	state.rate_limit_user("set_user_exemption", 30, 3600)
	user = _require_user(user)
	user_doc = frappe.get_doc("User", user)
	has_role = EXEMPT_ROLE in set(frappe.get_roles(user))
	if _coerce_bool(exempt):
		_ensure_exempt_role()
		if not has_role:
			user_doc.add_roles(EXEMPT_ROLE)
	elif has_role:
		user_doc.remove_roles(EXEMPT_ROLE)
	return admin_enforcement_view(user)


@frappe.whitelist(methods=["POST"])
def reset_enforcement_grace(user: str) -> dict:
	"""Restore one user's full grace budget. Returns the refreshed view-model."""
	refuse_if_core_native()
	frappe.only_for("System Manager")
	state.rate_limit_user("reset_enforcement_grace", 30, 3600)
	user = _require_user(user)
	boot.clear_enforcement_state(user)
	return admin_enforcement_view(user)
