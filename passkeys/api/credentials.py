# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Credential-management endpoints (DESIGN-v1 §8): list / rename / delete a
user's own passkeys, plus the per-user ``passkey_only_login`` switch (§9.3).
Authenticated, JSON bodies only. Identity is resolved strictly from
``frappe.session.user`` (never a client param); every credential ``name`` is
authorized by the ownership ladder (§3.0) with a **uniform not-found** so an
attacker learns nothing about other users' credentials.

This module carries no ceremony, so it does not import ``webauthn``. The
passkey-verified re-auth that mints management grants is the Phase-5 confirm
ceremony (§7.2); here the sudo window (§7.1) is the live gate for mutations.
"""

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import aaguid, session, state

# §11 dormant-shell guard. Imported from passkey.py, which is webauthn-free at
# module scope (the crypto engine is imported lazily inside its ceremony bodies),
# so this management module stays webauthn-free at import time (§1.3).
from passkeys.passkey import refuse_if_core_native

CREDENTIAL_DOCTYPE = "WebAuthn Credential"


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def list_credentials():
	"""Return the caller's own credentials for the management cards (§8.2). A
	read — not sudo-gated; ownership is implicit (filtered to the session user)."""
	refuse_if_core_native()  # §11 dormant-shell: 417 the moment core is native
	user = _require_user()
	state.rate_limit_user("list_credentials", 60, 60)  # §3.0 row 9: 60/min/user
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
	# §8.2: server-resolved provider display name from the vendored AAGUID
	# snapshot (aaguid.py — the single source of truth; the client's providerFor
	# prefers this over its own map lookup). None ⇒ generic "Unknown provider".
	for row in rows:
		row["provider"] = aaguid.provider_name(row.get("aaguid"))
	# §9.3: the caller's current passkey_only_login flag (0 when no handle row yet)
	# — the management toggle reads it from this payload (client parity with boot).
	return {
		"credentials": rows,
		"passkey_only_login": cint(
			frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login")
		),
	}


# ---------------------------------------------------------------------------
# rename (display-only — no sudo, §8.2)
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def rename_credential(name: str, label: str):
	"""Rename the caller's own credential (§8.2). Display-only, so no sudo gate;
	the DocType ``validate`` sanitizes + length-caps the label (stored-XSS)."""
	refuse_if_core_native()  # §11 dormant-shell: 417 the moment core is native
	user = _require_user()
	state.rate_limit_user("rename_credential", 20, 3600)  # §3.0 row 10: 20/hr/user
	doc = _own_credential(user, name)
	if not (label or "").strip():
		frappe.throw(_("A passkey name cannot be empty."), frappe.ValidationError)
	doc.label = label
	doc.save(ignore_permissions=True)
	return {"name": doc.name, "label": doc.label}


# ---------------------------------------------------------------------------
# delete (sudo-gated + last-credential guard, §7.4 / §8.3)
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def delete_credential(name: str):
	"""Delete the caller's own credential (§8.3). Sudo-gated (§7.4): a live
	full-sudo window is required — a passkey confirmation or password re-auth
	re-seeds it (§7.1). Refuses to drop the last passkey-capable credential of a
	``passkey_only_login`` user (or under site ``disable_user_pass_login``), the
	endpoint enforcement of the §2.2 handle-row floor (F3-3 / F-B3)."""
	refuse_if_core_native()  # §11 dormant-shell: 417 the moment core is native
	user = _require_user()
	state.rate_limit_user("delete_credential", 10, 3600)  # §3.0 row 11: 10/hr/user
	session.require_management_sudo(user)
	doc = _own_credential(user, name)
	_guard_last_credential(user, doc)
	frappe.delete_doc(CREDENTIAL_DOCTYPE, doc.name, ignore_permissions=True)
	# §8.3 out-of-band "passkey removed" notification + Activity Log rows are
	# owned by notifications.py (a later phase); the mutation itself is complete.
	return {"deleted": name}


def _guard_last_credential(user: str, doc) -> None:
	"""Refuse removing the final passkey-capable credential when the user would
	then have no login method (§8.3, census-mirroring ``validate_user_pass_login``).
	P2b covers the two released-branch levers: the per-user ``passkey_only_login``
	flag and site ``disable_user_pass_login``."""
	if not cint(doc.enabled):
		return  # a soft-disabled credential is not a login method; safe to drop
	# doc is enabled + still present, so it is included in this count.
	if frappe.db.count(CREDENTIAL_DOCTYPE, {"user": user, "enabled": 1}) > 1:
		return  # another enabled credential survives
	if _is_passkey_only(user) or frappe.get_system_settings("disable_user_pass_login"):
		frappe.throw(
			_(
				"This is your only passkey and passwordless login is on for your account — "
				"add another passkey (or turn off passkey-only login) before removing it."
			),
			frappe.ValidationError,
		)


# ---------------------------------------------------------------------------
# passkey_only_login switch (§9.3, F19) — passkey grant only
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def set_passkey_only_login(enabled):
	"""Toggle the caller's per-user password-login disable (§9.3). Gated on a
	single-use **passkey grant only** (F19): never a sudo window, never a
	password-minted grant — a password must never be sufficient to disable the
	"password is not sufficient" flag. Enable additionally requires ≥2 enabled
	passkeys (the ≥1 floor binds every writer via the handle-row ``validate``).

	Phase-5 note: the grant is minted by the confirm ceremony
	(``begin_confirmation`` / ``verify_confirmation`` for ``action`` =
	``passkeys.set_passkey_only_login``, §7.2) under the general
	``@passkey_protected`` decorator — that MINTER is not yet built. This
	endpoint wires the fully-real *consumer* guard (§7.2); until P5 ships the
	ceremony, a grant can only be produced by that phase's passkey assertion."""
	refuse_if_core_native()  # §11 dormant-shell: 417 the moment core is native
	user = _require_user()
	enabled_int = cint(enabled)
	payload = {"enabled": bool(enabled_int)}
	if not session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, payload):
		# Passkey-grade re-auth only — no sudo/password fallback offered (§9.3).
		# The 401 MUST carry the SERVER-computed fingerprint of THIS payload (A36):
		# the client echoes it verbatim into begin_confirmation, which binds the
		# minted grant's payload_hash to it, and the retry's consume recomputes the
		# same payload_hash({"enabled": bool}) — omitting it here shipped a None
		# fingerprint, so the grant could never match and the toggle never succeeded.
		session._raise_confirmation_required(
			session.SET_PASSKEY_ONLY_ACTION,
			methods=["passkey"],
			payload_fingerprint=session.payload_hash(payload),
		)

	if enabled_int and frappe.db.count(CREDENTIAL_DOCTYPE, {"user": user, "enabled": 1}) < 2:
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


def _require_user() -> str:
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	return user


def _own_credential(user: str, name: str):
	"""Load a credential the caller owns, else the **uniform not-found** (§3.0):
	never leak that another user's credential exists (no cross-user IDOR through
	the ``ignore_permissions`` writes)."""
	owner = frappe.db.get_value(CREDENTIAL_DOCTYPE, name, "user")
	if owner != user:
		raise frappe.DoesNotExistError(_("Passkey not found."))
	return frappe.get_doc(CREDENTIAL_DOCTYPE, name)


def _is_passkey_only(user: str) -> bool:
	return bool(frappe.db.get_value("WebAuthn User Handle", {"user": user}, "passkey_only_login"))


def _get_handle(user: str):
	name = frappe.db.get_value("WebAuthn User Handle", {"user": user})
	if not name:
		frappe.throw(
			_("Add a passkey before turning on passkey-only login."),
			frappe.ValidationError,
		)
	return frappe.get_doc("WebAuthn User Handle", name)
