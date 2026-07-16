# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Registration ceremony endpoints. Authenticated,
sudo-gated, JSON bodies only.

``webauthn`` (via ``passkeys.engine``) is imported **lazily inside the endpoint
bodies**: this module sits on no hook path, but the discipline keeps a
bad crypto wheel from ever reaching import time on a login.
"""

import base64
import hashlib
import json
import secrets

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import aaguid, policy, state
from passkeys.passkey import (
	CeremonyExpired,
	PasskeyConfirmationRequired,
	_enforce_request_host,
	refuse_if_core_native,
)

MANAGE_ACTION = "passkeys.manage"
REGISTRATION_INSERT_SAVEPOINT = "passkey_registration_insert"


# ---------------------------------------------------------------------------
# begin
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def begin_registration(flow: str = "explicit"):
	"""Issue creation options + cache the challenge. Identity is
	``frappe.session.user`` only — never a client param. Requires a valid sudo
	window: explicit needs any sudo window (weak-login only bootstraps a
	first credential); conditional-create needs a **password**-seeded window
	(the just-typed password is the freshness proof)."""
	refuse_if_core_native()  # dormant-shell (before the crypto engine import)
	from passkeys import engine

	if flow not in ("explicit", "conditional_create"):
		frappe.throw(_("Unknown registration flow."), frappe.ValidationError)

	user = frappe.session.user
	if user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	state.rate_limit_user("begin_registration", 20, 3600)  # 20/hr/user

	settings = frappe.get_cached_doc("Passkey Settings")
	_require_any_login_mode(settings)
	authorization = _require_sudo_for_registration(settings, user, flow)

	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		frappe.throw(_("Passkeys are not configured for this site."), frappe.ValidationError)
	origins = policy.resolve_expected_origins(settings, rp_id)
	_enforce_request_host(origins)

	credentials = _user_credentials(user)
	_enforce_max_per_user(settings, credentials, flow)

	handle = _get_or_create_handle(user)
	user_doc = frappe.get_cached_doc("User", user)
	options, challenge_b64 = engine.build_registration_options(
		rp_id=rp_id,
		rp_name=_rp_name(),
		user_id=base64.urlsafe_b64decode(_pad(handle.handle)),
		user_name=user,
		user_display_name=user_doc.full_name or user,
		exclude_credentials=[
			{"id": c.credential_id, "transports": _load_transports(c.transports)} for c in credentials
		],
		resident_key=policy.resident_key_for_flow(flow),
	)

	state_id = state.store_ceremony(
		{
			"v": 1,
			"type": "register",
			"flow": flow,
			"authorization": authorization,
			"user": user,
			"sid": frappe.session.sid,
			"challenge_b64": challenge_b64,
			"rp_id": rp_id,
			"origins": origins,
			"exclude_ids": [c.credential_id for c in credentials],
		}
	)
	return {"state_id": state_id, "options": options}


# ---------------------------------------------------------------------------
# complete
# ---------------------------------------------------------------------------


@frappe.whitelist(methods=["POST"])
def verify_registration(state_id: str, credential, label: str | None = None):
	"""Verify a creation response and persist a ``WebAuthn Credential`` row.
	Consumes the single-use challenge before verifying; the
	global ``credential_id_sha256`` unique index is the final arbiter of both
	duplicate registration and cross-account hijack."""
	refuse_if_core_native()  # dormant-shell (before the crypto engine import)
	from passkeys import engine

	# 20/hr/user — BEFORE the single-use consume, so a rate-limited
	# call never burns the caller's live ceremony (same ordering as verify_confirmation).
	state.rate_limit_user("verify_registration", 20, 3600)

	credential = _as_dict(credential)
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "register":
		raise CeremonyExpired(_("That took too long — please try again."))
	if record.get("sid") != frappe.session.sid or record.get("user") != frappe.session.user:
		raise frappe.AuthenticationError(_("Passkey registration could not be verified."))

	settings = frappe.get_cached_doc("Passkey Settings")
	_require_any_login_mode(settings)  # ladder step 3b: mid-ceremony disable fails closed
	_enforce_request_host(record.get("origins") or [])

	flow = record.get("flow", "explicit")
	result = engine.verify_registration(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		require_user_presence=(flow != "conditional_create"),
		require_user_verification=False,  # matrix layered below, not at the library
	)

	raw_id = base64.urlsafe_b64decode(_pad(result.credential_id))
	# The explicit flow pins resident_key="required" — a success without
	# credProps (Safari ships none, so result.discoverable is "Unknown") is STILL a
	# discoverable credential. Promote Unknown→Yes for explicit; conditional-create
	# keeps "Unknown" (rk genuinely unknown there).
	discoverable = result.discoverable
	if discoverable == "Unknown" and flow == "explicit":
		discoverable = "Yes"
	doc = frappe.get_doc(
		{
			"doctype": "WebAuthn Credential",
			"user": record["user"],
			"label": label or _default_label(result),
			"credential_id": result.credential_id,
			"credential_id_sha256": hashlib.sha256(raw_id).hexdigest(),
			"public_key": result.public_key,
			"sign_count": result.sign_count,
			"transports": json.dumps(result.transports),
			"aaguid": result.aaguid,
			"attestation_format": result.fmt,
			"attestation_object": result.attestation_object,
			"client_data_json": result.client_data_json,
			"backup_eligible": int(result.backup_eligible),
			"backup_state": int(result.backup_state),
			"uv_initialized": int(result.user_verified),  # this ceremony's UV bit
			"discoverable": discoverable,
			"authenticator_attachment": result.authenticator_attachment or "",
			"rp_id": record["rp_id"],  # descriptive only — verification never reads it
		}
	)
	handle = _insert_verified_credential(doc, settings, flow, record.get("authorization"))
	# out-of-band "passkey added" notice (label, time, IP) + Activity Log —
	# the compensating control for registration hijack. Exception-hardened inside.
	from passkeys import notifications

	notifications.notify_credential_added(
		record["user"], doc.label, ip=getattr(frappe.local, "request_ip", None)
	)
	return {
		"name": doc.name,
		"label": doc.label,
		"signal": {
			"user_handle": handle.handle,
			"credential_ids": _enabled_credential_ids(record["user"]),
			# name/display_name let the client fire signalCurrentUserDetails alongside
			# signalAllAcceptedCredentials (F2), so a freshly-enrolled passkey's provider label
			# matches the RP from the start.
			"name": record["user"],
			"display_name": frappe.db.get_value("User", record["user"], "full_name") or record["user"],
		},
	}


# ---------------------------------------------------------------------------
# gates
# ---------------------------------------------------------------------------


def _require_any_login_mode(settings) -> None:
	"""Registration is gated on ANY passkey login mode: a 2FA-only site's
	users must still be able to enroll."""
	if not (settings.login_with_passkey or settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkeys are not enabled."))


def _require_sudo_for_registration(settings, user: str, flow: str) -> str:
	window = state.get_sudo_window(frappe.session.sid)
	if not window or window.get("user") != user:
		_raise_confirmation_required()
	seeded_by = window.get("seeded_by")

	if flow == "conditional_create":
		# The silent upgrade rides the just-typed password's freshness.
		if seeded_by != "password":
			_raise_confirmation_required()
		return seeded_by

	# explicit add
	if seeded_by == "weak":
		# Restricted bootstrap: a weak (email-link / social) login may enroll
		# only a first-factor credential. In second-factor-only mode that login
		# would be vetoed on its next use while the user has no password/passkey
		# first factor, creating a self-lockout.
		if (
			not settings.login_with_passkey
			or _enabled_credential_count(user) > 0
			or not settings.passkey_allow_first_enrollment_on_weak_login
		):
			_raise_confirmation_required()
		# risk event: the weak-login bootstrap scope was used.
		from passkeys import notifications

		notifications.record_risk_event(
			notifications.RISK_WEAK_LOGIN_ENROLLMENT,
			user,
			f"first-enrollment bootstrap via weak login by {user}",
		)
		return seeded_by
	if seeded_by in ("password", "passkey", "reauth"):
		return seeded_by
	_raise_confirmation_required()


def _raise_confirmation_required() -> None:
	frappe.local.response["action"] = MANAGE_ACTION
	frappe.local.response["payload_fingerprint"] = None
	frappe.local.response["methods"] = ["passkey", "password"]
	raise PasskeyConfirmationRequired(_("Confirm it's you to manage passkeys."))


def _enforce_max_per_user(settings, credentials: list, flow: str) -> None:
	cap = int(settings.passkey_max_per_user or 10)
	if len(credentials) >= cap:
		frappe.throw(
			_("You have reached the maximum of {0} passkeys.").format(cap),
			frappe.ValidationError,
		)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _user_credentials(user: str) -> list:
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user},
		fields=["name", "credential_id", "transports"],
		order_by="creation asc",
	)


def _enabled_credential_count(user: str) -> int:
	return frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})


def _enabled_credential_ids(user: str) -> list[str]:
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user, "enabled": 1},
		pluck="credential_id",
		order_by="creation asc",
	)


def _get_or_create_handle(user: str):
	"""Return the user's handle with the global User -> Handle lock order."""
	_lock_user(user)
	return _get_or_create_handle_after_user_lock(user)


def _lock_user(user: str) -> None:
	if not frappe.db.get_value("User", user, "name", for_update=True):
		raise frappe.AuthenticationError(_("Passkey registration could not be verified."))


def _get_or_create_handle_after_user_lock(user: str):
	row = frappe.db.get_value(
		"WebAuthn User Handle",
		{"user": user},
		["name", "handle"],
		as_dict=True,
		for_update=True,
	)
	if row:
		return row
	handle = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
	doc = frappe.get_doc({"doctype": "WebAuthn User Handle", "user": user, "handle": handle})
	doc.insert(ignore_permissions=True)
	return doc


def _locking_user_credentials(user: str) -> list:
	"""Read the current credential census under locks, bypassing RR snapshots."""
	return frappe.db.get_values(
		"WebAuthn Credential",
		{"user": user},
		["name", "credential_id", "transports", "enabled"],
		as_dict=True,
		order_by="creation asc",
		for_update=True,
	)


def _insert_verified_credential(doc, settings, flow: str, authorization: str | None = None):
	"""Atomically enforce authorization, the per-user cap, and persistence."""
	_lock_user(doc.user)
	handle = _get_or_create_handle_after_user_lock(doc.user)
	credentials = _locking_user_credentials(doc.user)
	if authorization == "weak":
		# Several ceremonies can begin while the census is zero. Recheck the
		# restricted bootstrap under the same User lock used for insertion so only
		# one weak-login ceremony can create the first enabled credential.
		if (
			flow != "explicit"
			or not cint(settings.login_with_passkey)
			or not cint(settings.passkey_allow_first_enrollment_on_weak_login)
			or any(cint(row.enabled) for row in credentials)
		):
			_raise_confirmation_required()
	_enforce_max_per_user(settings, credentials, flow)

	frappe.db.savepoint(REGISTRATION_INSERT_SAVEPOINT)
	try:
		doc.insert(ignore_permissions=True)
	except (frappe.UniqueValidationError, frappe.DuplicateEntryError):
		# Global uniqueness fails closed under worker races AND cross-account
		# hijack. Roll back only this insert; callers may have unrelated work in
		# the surrounding request transaction.
		frappe.db.rollback(save_point=REGISTRATION_INSERT_SAVEPOINT)
		frappe.db.release_savepoint(REGISTRATION_INSERT_SAVEPOINT)
		raise frappe.AuthenticationError(_("This passkey is already registered."))
	else:
		frappe.db.release_savepoint(REGISTRATION_INSERT_SAVEPOINT)
	return handle


def _default_label(result) -> str:
	# label precedence: AAGUID provider name from the vendored
	# snapshot (e.g. "Apple Passwords"), else the neutral attachment-derived
	# default. Zero/unknown AAGUID is never an error — just the fallback.
	# The DocType validate sanitizes + length-caps whatever lands here.
	provider = aaguid.provider_name(result.aaguid)
	if provider:
		return provider
	if result.authenticator_attachment == "platform":
		return _("Device passkey")
	return _("Passkey")


def _load_transports(raw) -> list:
	if not raw:
		return []
	try:
		value = json.loads(raw)
	except (TypeError, ValueError):
		return []
	return value if isinstance(value, list) else []


def _rp_name() -> str:
	"""RP display name shown in the OS passkey sheet — the site's brand name,
	falling back to the site id."""
	return frappe.get_website_settings("app_name") or frappe.local.site or "Frappe"


def _as_dict(value):
	return json.loads(value) if isinstance(value, str) else value


def _pad(b64url: str) -> str:
	return b64url + "=" * (-len(b64url) % 4)
