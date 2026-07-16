# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Credential-management endpoints: list / rename / delete a
user's own passkeys, plus the per-user ``passkey_only_login`` switch.
Authenticated, JSON bodies only. Identity is resolved strictly from
``frappe.session.user`` (never a client param); every credential ``name`` is
authorized by the ownership ladder with a **uniform not-found** so an
attacker learns nothing about other users' credentials.

This module carries no ceremony, so it does not import ``webauthn``. The
passkey-verified re-auth that mints management grants is the Phase-5 confirm
ceremony; here the sudo window is the live gate for mutations.
"""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import aaguid, session, state

# dormant-shell guard. Imported from passkey.py, which is webauthn-free at
# module scope (the crypto engine is imported lazily inside its ceremony bodies),
# so this management module stays webauthn-free at import time.
from passkeys.passkey import refuse_if_core_native
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import (
	lock_login_floor,
	lock_passkey_mode_floor,
)

CREDENTIAL_DOCTYPE = "WebAuthn Credential"


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def list_credentials():
	"""Return the caller's own credentials for the management cards. A
	read — not sudo-gated; ownership is implicit (filtered to the session user)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = session.require_authed_user()
	state.rate_limit_user("list_credentials", 60, 60)  # 60/min/user
	rows = frappe.get_all(
		CREDENTIAL_DOCTYPE,
		filters={"user": user},
		fields=[
			"name",
			"label",
			"enabled",
			"flagged",
			"flagged_reason",
			"backup_state",
			"backup_eligible",
			"discoverable",
			"aaguid",
			"last_used_at",
			"creation",
		],
		order_by="creation asc",
	)
	# Server-resolved provider display name from the vendored AAGUID
	# snapshot (aaguid.py — the single source of truth; the client's providerFor
	# prefers this over its own map lookup). None ⇒ generic "Unknown provider".
	for row in rows:
		row["provider"] = aaguid.provider_name(row.get("aaguid"))
	# The caller's current passkey_only_login flag (0 when no handle row yet)
	# — the management toggle reads it from this payload (client parity with boot).
	return {
		"credentials": rows,
		"passkey_only_login": cint(
			frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login")
		),
	}


# ---------------------------------------------------------------------------
# rename (display-only — no sudo)
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def rename_credential(name: str, label: str):
	"""Rename the caller's own credential. Display-only, so no sudo gate;
	the DocType ``validate`` sanitizes + length-caps the label (stored-XSS)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = session.require_authed_user()
	state.rate_limit_user("rename_credential", 20, 3600)  # 20/hr/user
	doc = _own_credential(user, name)
	if not (label or "").strip():
		frappe.throw(_("A passkey name cannot be empty."), frappe.ValidationError)
	doc.label = label
	doc.save(ignore_permissions=True)
	return {"name": doc.name, "label": doc.label}


# ---------------------------------------------------------------------------
# delete (sudo-gated + last-credential guard)
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def delete_credential(name: str):
	"""Delete the caller's own credential. Sudo-gated: a live
	full-sudo window is required — a passkey confirmation or password re-auth
	re-seeds it. Refuses to drop the last passkey-capable credential of a
	``passkey_only_login`` user (or under site ``disable_user_pass_login``), the
	endpoint enforcement of the handle-row floor."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = session.require_authed_user()
	state.rate_limit_user("delete_credential", 10, 3600)  # 10/hr/user
	session.require_management_sudo(user)
	doc = _own_credential(user, name)
	_guard_last_credential(user, doc)
	frappe.delete_doc(CREDENTIAL_DOCTYPE, doc.name, ignore_permissions=True)
	# the out-of-band "passkey removed" notification + Activity Log row are owned by
	# notifications.py, fired off this delete via the WebAuthn Credential after_delete hook.
	return {"deleted": name}


def _guard_last_credential(user: str, doc) -> None:
	"""Refuse removing the final passkey-capable credential when the user would
	then have no login method (census-mirroring ``validate_user_pass_login``).
	It covers the two released-branch levers: the per-user ``passkey_only_login``
	flag and site ``disable_user_pass_login``. Locks first — overlapping removals
	serialize on the handle row and re-check against locking reads, so two rapid
	deletes can never both see "another credential survives" and together drop
	every credential of a passkey-only user (the retry-click lockout)."""
	passkey_only, enabled_names = lock_login_floor(user)
	if doc.name not in enabled_names:
		return  # a soft-disabled credential is not a login method; safe to drop
	# doc is enabled + still present (fresh, under lock), so it is in this census.
	if len(enabled_names) > 1:
		return  # another enabled credential survives
	if passkey_only or frappe.get_system_settings("disable_user_pass_login"):
		frappe.throw(
			_(
				"This is your only passkey and passwordless login is on for your account — "
				"add another passkey (or turn off passkey-only login) before removing it."
			),
			frappe.ValidationError,
		)


# ---------------------------------------------------------------------------
# passkey_only_login switch — passkey grant only
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def set_passkey_only_login(enabled):
	"""Toggle the caller's per-user password-login disable. Gated on a
	single-use **passkey grant only**: never a sudo window, never a
	password-minted grant — a password must never be sufficient to disable the
	"password is not sufficient" flag. Enable additionally requires ≥2 enabled
	passkeys (the ≥1 floor binds every writer via the handle-row ``validate``)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = session.require_authed_user()
	enabled_int = cint(enabled)
	payload = {"enabled": bool(enabled_int)}
	if not session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, payload):
		# Passkey-grade re-auth only — no sudo/password fallback offered.
		# The 401 MUST carry the SERVER-computed fingerprint of THIS payload:
		# the client echoes it verbatim into begin_confirmation, which binds the
		# minted grant's payload_hash to it, and the retry's consume recomputes the
		# same payload_hash({"enabled": bool}) — omitting it here shipped a None
		# fingerprint, so the grant could never match and the toggle never succeeded.
		session._raise_confirmation_required(
			session.SET_PASSKEY_ONLY_ACTION,
			methods=["passkey"],
			payload_fingerprint=session.payload_hash(payload),
			action_label=_("Change passkey-only login"),
			parameter_summary=[
				{"label": _("Passkey-only login"), "value": _("On") if enabled_int else _("Off")}
			],
		)

	# The site-mode lock always comes before the per-user handle/credential lock.
	# A concurrent settings save that disables both modes then either observes this
	# flag or makes this enable fail after it wakes.
	mode_enabled = lock_passkey_mode_floor()
	if enabled_int and not mode_enabled:
		frappe.throw(
			_("Enable a passkey login mode before turning on passkey-only login."),
			frappe.ValidationError,
		)

	# Hold the invariant lock before checking the enable floor: the census must
	# be a locking read, or a concurrent delete's commit stays invisible to this
	# transaction's REPEATABLE READ snapshot and the flag flips on while the
	# last credential disappears — the mirror image of the delete-delete race.
	enabled_credentials = lock_login_floor(user)[1]
	if enabled_int and len(enabled_credentials) < 2:
		frappe.throw(
			_(
				"Enabling passkey-only login needs at least two enabled passkeys, so a lost device never locks you out."
			),
			frappe.ValidationError,
		)

	handle = _get_handle(user)
	handle.passkey_only_login = enabled_int
	handle.save(ignore_permissions=True)  # handle-row validate enforces the ≥1 floor
	return {"passkey_only_login": cint(handle.passkey_only_login)}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _own_credential(user: str, name: str):
	"""Load a credential the caller owns, else the **uniform not-found**:
	never leak that another user's credential exists (no cross-user IDOR through
	the ``ignore_permissions`` writes)."""
	owner = frappe.db.get_value(CREDENTIAL_DOCTYPE, name, "user")
	if owner != user:
		raise frappe.DoesNotExistError(_("Passkey not found."))
	return frappe.get_doc(CREDENTIAL_DOCTYPE, name)


def _get_handle(user: str):
	name = frappe.db.get_value("WebAuthn User Handle", {"user": user})
	if not name:
		frappe.throw(
			_("Add a passkey before turning on passkey-only login."),
			frappe.ValidationError,
		)
	return frappe.get_doc("WebAuthn User Handle", name)
