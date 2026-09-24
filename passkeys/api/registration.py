# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Registration ceremony endpoints: authenticated, sudo-gated, JSON bodies only.
``webauthn`` (via ``passkeys.engine``) is imported lazily inside the endpoint bodies."""

import base64
import hashlib
import json
import secrets

import frappe
from frappe import _
from frappe.utils import cint

from passkeys import aaguid, ceremony, policy, session, state
from passkeys.errors import CeremonyExpired, CeremonyFailed, refuse_if_core_native

REGISTRATION_INSERT_SAVEPOINT = "passkey_registration_insert"


@frappe.whitelist(methods=["POST"])
def begin_registration(flow: str = "explicit"):
	"""Issue creation options and cache the challenge for ``frappe.session.user`` (never a
	client param). Explicit needs a full sudo window, or a weak login's restricted
	first-enrollment bootstrap; conditional-create needs a **password**-seeded window (the
	just-typed password is the freshness proof)."""
	refuse_if_core_native()
	user = session.require_authed_user()
	_refuse_impersonated_session()
	if flow not in ("explicit", "conditional_create"):
		frappe.throw(_("Unknown registration flow."), frappe.ValidationError)
	state.rate_limit_user("begin_registration", 20, 3600)
	from passkeys import engine

	settings = frappe.get_cached_doc("Passkey Settings")
	_require_any_login_mode(settings)
	authorization = _require_sudo_for_registration(settings, user, flow)

	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		frappe.throw(_("Passkeys are not configured for this site."), frappe.ValidationError)
	origins = policy.resolve_expected_origins(settings, rp_id)
	ceremony.enforce_request_host(origins, error=CeremonyFailed)

	credentials = _user_credentials(user)
	_enforce_max_per_user(settings, credentials)

	handle = _get_or_create_handle(user)
	options, challenge_b64 = engine.build_registration_options(
		rp_id=rp_id,
		rp_name=frappe.get_website_settings("app_name") or frappe.local.site,
		user_id=ceremony.b64url_decode(handle.handle, error=CeremonyFailed),
		user_name=user,
		user_display_name=frappe.get_cached_doc("User", user).full_name or user,
		exclude_credentials=ceremony.credential_descriptors(credentials),
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
		}
	)
	return {"state_id": state_id, "options": options}


@frappe.whitelist(methods=["POST"])
def verify_registration(state_id: str, credential: object, label: str | None = None):
	"""Verify a creation response and persist a ``WebAuthn Credential`` row. The global
	``credential_id_sha256`` unique index is the final arbiter of both duplicate
	registration and cross-account hijack."""
	refuse_if_core_native()
	session.require_authed_user()
	_refuse_impersonated_session()
	# before the single-use consume, so a rate-limited call never burns the live ceremony
	state.rate_limit_user("verify_registration", 20, 3600)
	from passkeys import engine, notifications

	credential = ceremony.require_credential_dict(
		credential, _("Passkey registration could not be verified."), error=CeremonyFailed
	)
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "register":
		raise CeremonyExpired(_("That took too long — please try again."))
	if record.get("sid") != frappe.session.sid or record.get("user") != frappe.session.user:
		raise CeremonyFailed(_("Passkey registration could not be verified."))
	settings = frappe.get_cached_doc("Passkey Settings")
	_require_any_login_mode(settings)  # a mid-ceremony disable fails closed
	ceremony.enforce_request_host(record.get("origins") or [], error=CeremonyFailed)

	flow = record["flow"]
	result = engine.verify_registration(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		require_user_presence=(flow != "conditional_create"),
	)
	# The explicit flow requires a resident key, so a success without credProps (Safari)
	# is still discoverable.
	discoverable = result.discoverable
	if discoverable == "Unknown" and flow == "explicit":
		discoverable = "Yes"
	user = record["user"]
	doc = frappe.get_doc(
		{
			"doctype": "WebAuthn Credential",
			"user": user,
			"label": label or _default_label(result),
			"credential_id": result.credential_id,
			"credential_id_sha256": hashlib.sha256(ceremony.b64url_decode(result.credential_id)).hexdigest(),
			"public_key": result.public_key,
			"sign_count": result.sign_count,
			"transports": json.dumps(result.transports),
			"aaguid": result.aaguid,
			"attestation_format": result.fmt,
			"attestation_object": result.attestation_object,
			"client_data_json": result.client_data_json,
			"backup_eligible": int(result.backup_eligible),
			"backup_state": int(result.backup_state),
			"uv_initialized": int(result.user_verified),
			"discoverable": discoverable,
			"authenticator_attachment": result.authenticator_attachment or "",
			"rp_id": record["rp_id"],  # descriptive only — verification never reads it
		}
	)
	handle = _insert_verified_credential(doc, settings, record.get("authorization"))
	# out-of-band "passkey added" notice: the compensating control for registration hijack
	notifications.notify_credential_added(user, doc.label, ip=ceremony.request_ip())
	return {
		"name": doc.name,
		"label": doc.label,
		# signalAllAcceptedCredentials + signalCurrentUserDetails for the new passkey
		"signal": {
			"user_handle": handle.handle,
			"credential_ids": frappe.get_all(
				"WebAuthn Credential",
				filters={"user": user, "enabled": 1},
				pluck="credential_id",
				order_by="creation asc",
			),
			"name": user,
			"display_name": frappe.db.get_value("User", user, "full_name") or user,
		},
	}


def _refuse_impersonated_session() -> None:
	"""An impersonating Administrator must never leave behind a credential the user did
	not create (the impersonated session is weak-seeded, so it would otherwise qualify
	for the first-enrollment bootstrap)."""
	if (frappe.session.get("data") or {}).get("impersonated_by"):
		raise frappe.PermissionError(_("Passkeys cannot be registered while impersonating a user."))


def _require_any_login_mode(settings) -> None:
	"""Either login mode allows enrollment: a 2FA-only site's users must enroll too."""
	if not (cint(settings.login_with_passkey) or cint(settings.passkey_as_second_factor)):
		raise CeremonyFailed(_("Passkeys are not enabled."))


def _require_sudo_for_registration(settings, user: str, flow: str) -> str:
	"""The sudo window's seeding class that authorizes this registration, or the 401
	confirmation contract."""
	seeded_by = (session.get_window(user) or {}).get("seeded_by")
	if flow == "conditional_create":
		is_allowed = seeded_by == "password"
	elif seeded_by == "weak":
		has_enabled_credential = frappe.db.exists("WebAuthn Credential", {"user": user, "enabled": 1})
		is_allowed = _is_weak_bootstrap_allowed(settings, has_enabled_credential)
	else:
		is_allowed = seeded_by in session.FULL_SUDO_METHODS
	if not is_allowed:
		session._raise_confirmation_required(session.MANAGE_ACTION, methods=["passkey", "password"])
	if seeded_by == "weak":
		from passkeys import notifications

		notifications.record_risk_event(
			notifications.RISK_WEAK_LOGIN_ENROLLMENT,
			user,
			f"first-enrollment bootstrap via weak login by {user}",
		)
	return seeded_by


def _is_weak_bootstrap_allowed(settings, has_enabled_credential) -> bool:
	"""A weak (email-link / social) login may enroll only a first credential, and only as a
	first factor: in second-factor-only mode that login would be vetoed on its next use,
	locking the user out."""
	return bool(
		cint(settings.login_with_passkey)
		and cint(settings.passkey_allow_first_enrollment_on_weak_login)
		and not has_enabled_credential
	)


def _enforce_max_per_user(settings, credentials: list) -> None:
	cap = int(settings.passkey_max_per_user or 10)
	if len(credentials) >= cap:
		frappe.throw(
			_("You have reached the maximum of {0} passkeys.").format(cap),
			frappe.ValidationError,
		)


def _user_credentials(user: str, *, for_update: bool = False) -> list:
	"""Every credential of the user, disabled ones included (they count toward the cap
	and stay excluded). ``for_update`` reads past the transaction's snapshot."""
	return frappe.db.get_values(
		"WebAuthn Credential",
		{"user": user},
		["name", "credential_id", "transports", "enabled"],
		as_dict=True,
		order_by="creation asc",
		for_update=for_update,
	)


def _get_or_create_handle(user: str):
	"""The user's handle, taken in the global User → Handle lock order."""
	if not frappe.db.get_value("User", user, "name", for_update=True):
		raise CeremonyFailed(_("Passkey registration could not be verified."))
	row = frappe.db.get_value(
		"WebAuthn User Handle", {"user": user}, ["name", "handle"], as_dict=True, for_update=True
	)
	if row:
		return row
	handle = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
	doc = frappe.get_doc({"doctype": "WebAuthn User Handle", "user": user, "handle": handle})
	doc.insert(ignore_permissions=True)
	return doc


def _insert_verified_credential(doc, settings, authorization: str | None = None):
	"""Atomically re-check authorization and the per-user cap under the User lock, then
	persist."""
	handle = _get_or_create_handle(doc.user)
	credentials = _user_credentials(doc.user, for_update=True)
	# Several weak-login ceremonies can begin while the census is zero; only one may
	# create the first enabled credential.
	if authorization == "weak" and not _is_weak_bootstrap_allowed(
		settings, any(cint(row.enabled) for row in credentials)
	):
		raise CeremonyFailed(
			_("Passkey registration could not be completed. Re-authenticate and begin again.")
		)
	_enforce_max_per_user(settings, credentials)

	frappe.db.savepoint(REGISTRATION_INSERT_SAVEPOINT)
	try:
		doc.insert(ignore_permissions=True)
	except (frappe.UniqueValidationError, frappe.DuplicateEntryError):
		# Global uniqueness fails closed under worker races and cross-account hijack.
		# Roll back only this insert, not the surrounding request transaction.
		frappe.db.rollback(save_point=REGISTRATION_INSERT_SAVEPOINT)
		frappe.db.release_savepoint(REGISTRATION_INSERT_SAVEPOINT)
		raise CeremonyFailed(_("This passkey is already registered."))
	frappe.db.release_savepoint(REGISTRATION_INSERT_SAVEPOINT)
	return handle


def _default_label(result) -> str:
	"""The AAGUID provider name (e.g. "Apple Passwords"), else a neutral default."""
	provider = aaguid.provider_name(result.aaguid)
	if provider:
		return provider
	if result.authenticator_attachment == "platform":
		return _("Device passkey")
	return _("Passkey")
