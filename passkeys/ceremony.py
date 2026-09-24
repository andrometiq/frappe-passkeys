# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Ceremony primitives shared by the login, confirmation and registration endpoints:
request-host membership, credential-envelope parsing, credential lookup and locking,
and the post-assertion credential advance. Webauthn-free: the endpoints import
``engine`` lazily, never this module.

Every refusal raises ``error``: the uniform ``AuthenticationError`` for the Guest login
wire, and ``errors.CeremonyFailed`` from signed-in callers, since Frappe signs a user
out on the exact base class."""

import base64
import binascii
import hashlib
import json

import frappe
from frappe import _
from frappe.utils import cint, now_datetime

from passkeys import policy

LOCKED_CREDENTIAL_FIELDS = (
	"name",
	"user",
	"enabled",
	"public_key",
	"sign_count",
	"backup_eligible",
	"uv_initialized",
)


def enforce_request_host(origins: list, *, error=frappe.AuthenticationError) -> None:
	"""Fail-closed host membership. No-ops without an HTTP request (direct-call unit
	paths): the library's ``expected_origin`` check against clientDataJSON is the
	binding enforcement; this is the ops-diagnosable pre-check."""
	request = getattr(frappe.local, "request", None)
	headers = getattr(request, "headers", None)
	origin = headers.get("Origin") if headers is not None else None
	if origin is None:
		return
	if origin not in origins:
		frappe.log_error(
			title="passkeys: request host not in configured origins",
			message=f"request origin {origin} not in {origins}",
		)
		raise error(_("Passkeys aren't set up for this site."))


def request_ip() -> str | None:
	return getattr(frappe.local, "request_ip", None)


def b64url_decode(value: str, *, error=frappe.AuthenticationError) -> bytes:
	"""Base64url-decode (tolerating stripped padding). A malformed value raises
	``error``, never a raw decode error: a 500 would break the uniform-401 contract and,
	after the single-use consume, burn the ceremony instead of re-arming it."""
	try:
		return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
	except (binascii.Error, ValueError, TypeError) as exc:
		raise error(_("Passkey could not be verified.")) from exc


def require_credential_dict(value, message, *, error=frappe.AuthenticationError):
	"""Parse a client credential (JSON string or decoded dict) and check its envelope
	shape before any state is consumed; any malformation raises ``message``."""
	try:
		parsed = json.loads(value) if isinstance(value, str) else value
	except ValueError as exc:
		raise error(message) from exc
	response = parsed.get("response") if isinstance(parsed, dict) else None
	if not isinstance(response, dict):
		raise error(message)
	try:
		client_data = json.loads(b64url_decode(response.get("clientDataJSON"), error=error))
	except (frappe.AuthenticationError, ValueError) as exc:
		raise error(message) from exc
	if not isinstance(client_data, dict):
		raise error(message)
	return parsed


def enabled_credentials(user: str) -> list:
	"""The user's enabled credentials (id + sha + transports); empty ⇒ no passkey."""
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user, "enabled": 1},
		fields=["credential_id", "credential_id_sha256", "transports"],
	)


def credential_descriptors(rows: list) -> list:
	"""``{id, transports}`` entries for an ``allowCredentials`` / ``excludeCredentials`` list."""
	return [{"id": row.credential_id, "transports": json.loads(row.transports or "[]")} for row in rows]


def credential_id_sha256(credential: dict, *, error=frappe.AuthenticationError) -> str:
	"""SHA-256 of the asserted credential id — the lookup key of every stored credential."""
	credential_id = credential.get("id") or credential.get("rawId")
	if not credential_id:
		raise error(_("Passkey could not be verified."))
	return hashlib.sha256(b64url_decode(credential_id, error=error)).hexdigest()


def lock_enabled_user(user: str) -> bool:
	"""Lock the account row that anchors every authentication lock sequence."""
	return bool(cint(frappe.db.get_value("User", user, "enabled", for_update=True)))


def lock_credential(credential_sha256: str):
	"""Lock and read a credential row by id hash; call after :func:`lock_enabled_user`."""
	return frappe.db.get_value(
		"WebAuthn Credential",
		{"credential_id_sha256": credential_sha256},
		LOCKED_CREDENTIAL_FIELDS,
		as_dict=True,
		for_update=True,
	)


def lock_allowed_credential(record: dict, credential: dict, user: str, *, error=frappe.AuthenticationError):
	"""Resolve and lock the asserted credential of a ceremony started for a known ``user``.
	It must be in THIS ceremony's allow-list (the credential-substitution defence), belong to
	``user``, be enabled, and any returned ``userHandle`` must map to ``user``."""
	credential_sha256 = credential_id_sha256(credential, error=error)
	if credential_sha256 not in (record.get("allow_sha256") or []):
		raise error(_("Passkey could not be verified."))
	if not lock_enabled_user(user):
		raise error(_("Passkey could not be verified."))
	row = lock_credential(credential_sha256)
	if not row or row.user != user or not cint(row.enabled) or not has_matching_user_handle(credential, user):
		raise error(_("Passkey could not be verified."))
	return row


def get_handle_user(user_handle, *, for_update: bool = False) -> str | None:
	"""The User a WebAuthn user handle belongs to. A non-string handle (a client-supplied
	list or dict would read as a query operator) matches nobody."""
	if not isinstance(user_handle, str) or not user_handle:
		return None
	return frappe.db.get_value("WebAuthn User Handle", {"handle": user_handle}, "user", for_update=for_update)


def has_matching_user_handle(credential: dict, user: str) -> bool:
	"""WebAuthn L3 §7.2 when the user was identified before the ceremony: a returned
	``userHandle`` must map to that user. Authenticators may omit it."""
	user_handle = credential["response"].get("userHandle")
	return user_handle in (None, "") or get_handle_user(user_handle) == user


def advance_credential(
	name: str,
	result,
	*,
	sign_count_hard_fail: bool = False,
	values: dict | None = None,
	error=frappe.AuthenticationError,
) -> None:
	"""Persist the upward-only sign count, backup state, last-used bookkeeping and any
	extra ``values`` after a verified assertion.

	Re-reading the row ``FOR UPDATE`` reclassifies a duplicate assertion that was verified
	against stale state before any session or grant is minted. A regression flags the
	credential and notifies the owner on the unflagged→flagged edge only."""
	current = frappe.db.get_value(
		"WebAuthn Credential", name, ["sign_count", "flagged", "user", "label"], as_dict=True, for_update=True
	)
	if not current:
		raise error(_("Passkey could not be verified."))
	stored, asserted = cint(current.sign_count), cint(result.new_sign_count)
	klass = policy.classify_sign_count(stored, asserted)
	regression = klass == policy.SIGN_COUNT_REGRESSION
	if klass == policy.SIGN_COUNT_REPLAY or (regression and sign_count_hard_fail):
		raise error(_("Passkey could not be verified."))
	values = {
		**(values or {}),
		"sign_count": policy.sign_count_to_store(stored, asserted),
		"backup_state": int(result.backup_state),
		"last_used_at": now_datetime(),
		"last_used_ip": request_ip(),
	}
	if regression:
		values.update(flagged=1, flagged_reason="sign_count_regression")
	frappe.db.set_value("WebAuthn Credential", name, values, update_modified=False)
	if regression and not cint(current.flagged):
		from passkeys import notifications

		notifications.notify_credential_flagged(current.user, current.label, "sign_count_regression")
