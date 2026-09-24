# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Ceremony primitives shared by the login, confirmation and registration endpoints:
request-host membership, credential-envelope parsing, the enabled-credential set,
the User row lock that starts every lock sequence, and the post-assertion credential
advance. Webauthn-free: the endpoints import ``engine`` lazily, never this module.

Every refusal raises ``error``: the uniform ``AuthenticationError`` for the Guest login
wire, and ``errors.CeremonyFailed`` from signed-in callers, since Frappe signs a user
out on the exact base class."""

import base64
import binascii
import json

import frappe
from frappe import _
from frappe.utils import cint, now_datetime

from passkeys import policy


def enforce_request_host(origins: list, *, error=frappe.AuthenticationError) -> None:
	"""Fail-closed host membership. No-ops without an HTTP request (direct-call unit
	paths): the library's ``expected_origin`` check against clientDataJSON is the
	binding enforcement; this is the ops-diagnosable pre-check that also powers the
	begin-side uniform 401."""
	origin = request_origin()
	if origin is None:
		return
	if origin not in origins:
		# Log every refusal; the list holds only configured exact origins, and the
		# wire answer stays uniform.
		frappe.log_error(
			title="passkeys: request host not in configured origins",
			message=f"request origin {origin} not in {origins}",
		)
		raise error(_("Passkeys aren't set up for this site."))


def request_origin() -> str | None:
	request = getattr(frappe.local, "request", None)
	headers = getattr(request, "headers", None) if request is not None else None
	return headers.get("Origin") if headers is not None else None


def request_ip() -> str | None:
	return getattr(frappe.local, "request_ip", None)


def b64url_decode(value: str, *, error=frappe.AuthenticationError) -> bytes:
	"""Base64url-decode a credential id (tolerating stripped padding). A malformed
	value raises ``error``, never a raw decode error: a 500
	would break the uniform-401 contract, and in ``verify_second_factor`` (after the
	single-use consume) it would burn the 2FA state instead of re-arming."""
	try:
		return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
	except (binascii.Error, ValueError, TypeError) as exc:
		raise error(_("Passkey could not be verified.")) from exc


def require_credential_dict(value, message, *, error=frappe.AuthenticationError):
	"""Parse a client credential (JSON string or decoded dict) and check its envelope
	shape before any state is consumed; any malformation raises ``message``."""
	try:
		parsed = json.loads(value) if isinstance(value, str) else value
	except (json.JSONDecodeError, ValueError) as exc:
		raise error(message) from exc
	# JSON request bodies may already be decoded, so validate the final value.
	if not isinstance(parsed, dict):
		raise error(message)
	response = parsed.get("response")
	if not isinstance(response, dict):
		raise error(message)
	try:
		client_data_json = response.get("clientDataJSON")
		client_data = base64.urlsafe_b64decode(client_data_json + "=" * (-len(client_data_json) % 4))
		decoded = json.loads(client_data)
	except (binascii.Error, TypeError, ValueError) as exc:
		raise error(message) from exc
	if not isinstance(decoded, dict):
		raise error(message)
	return parsed


def enabled_credentials(user: str) -> list:
	"""The user's enabled credentials (id + sha + transports) for an allow-list.
	Empty ⇒ the user has no passkey."""
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user, "enabled": 1},
		fields=["credential_id", "credential_id_sha256", "transports"],
	)


def lock_enabled_user(user: str) -> bool:
	"""Lock the account row that anchors every authentication lock sequence."""
	return bool(cint(frappe.db.get_value("User", user, "enabled", for_update=True)))


def get_handle_user(user_handle: str, *, for_update: bool = False) -> str | None:
	"""The User a WebAuthn user handle belongs to."""
	return frappe.db.get_value("WebAuthn User Handle", {"handle": user_handle}, "user", for_update=for_update)


def has_matching_user_handle(credential: dict, user: str) -> bool:
	"""WebAuthn L3 §7.2 when the user was identified before the ceremony: a returned
	``userHandle`` must map to that user. Authenticators may omit it."""
	user_handle = credential["response"].get("userHandle")
	if user_handle in (None, ""):
		return True
	return isinstance(user_handle, str) and get_handle_user(user_handle) == user


def advance_credential(
	name: str, result, *, sign_count_hard_fail: bool = False, error=frappe.AuthenticationError
) -> None:
	"""Persist the upward-only sign-count, refreshed backup state, and last-used
	bookkeeping after a successful assertion.

	Re-reading the row ``FOR UPDATE`` reclassifies a duplicate assertion that was
	verified against stale state before any session or grant is minted."""
	current = frappe.db.get_value("WebAuthn Credential", name, ["sign_count"], as_dict=True, for_update=True)
	if not current:
		raise error(_("Passkey could not be verified."))
	klass = policy.classify_sign_count(cint(current.sign_count), cint(result.new_sign_count))
	if klass == policy.SIGN_COUNT_REPLAY:
		raise error(_("Passkey could not be verified."))
	regression = klass == policy.SIGN_COUNT_REGRESSION
	if regression and sign_count_hard_fail:
		raise error(_("Passkey could not be verified."))
	values = {
		"sign_count": policy.sign_count_to_store(cint(current.sign_count), cint(result.new_sign_count)),
		"backup_state": int(result.backup_state),
		"last_used_at": now_datetime(),
		"last_used_ip": request_ip(),
	}
	newly_flagged = apply_sign_count_flag(name, regression, values)
	frappe.db.set_value("WebAuthn Credential", name, values, update_modified=False)
	notify_if_newly_flagged(name, newly_flagged)


def apply_sign_count_flag(name: str, regression: bool, values: dict) -> bool:
	"""Fold a sign-count regression into a pending credential-write ``values`` dict
	and report whether this is the unflagged→flagged rising edge. Shared by
	:func:`advance_credential` and the uv-setup completion so both flag identically."""
	if not regression:
		return False
	values["flagged"] = 1
	values["flagged_reason"] = "sign_count_regression"
	return not cint(frappe.db.get_value("WebAuthn Credential", name, "flagged"))


def notify_if_newly_flagged(name: str, newly_flagged: bool) -> None:
	"""Send the "passkey flagged" notice on the unflagged→flagged edge only, so a
	repeatedly-regressing credential does not re-notify the owner."""
	if not newly_flagged:
		return
	from passkeys import notifications

	row = frappe.db.get_value("WebAuthn Credential", name, ["user", "label"], as_dict=True)
	if row:
		notifications.notify_credential_flagged(row.user, row.label, "sign_count_regression")
