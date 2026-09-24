# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""WebAuthn engine — py_webauthn options/verify wrappers + app-side policy
(folds into ``frappe/passkey.py``). The only top-level ``import webauthn``: serving
workers import this lazily inside ceremony endpoint bodies, so a broken crypto wheel
never reaches a hook chain.

py_webauthn (>=2.8,<3) behaviors honored here (pinned by ``passkeys/tests/vectors/``):

* ``verify_authentication_response`` hard-rejects sign-count regressions
  *internally*; we pass ``credential_current_sign_count=0`` to disable that and
  enforce the log+flag policy app-side.
* ``InvalidBackupFlags`` is a **sibling** exception (not a subclass) — its own
  ``except`` branch, else a naive handler turns a 401 into a 500.
* ``clientExtensionResults`` is dropped at parse — credProps is read from the
  **raw** credential JSON.
* ``crossOrigin`` is accepted by the library and ``topOrigin`` is never parsed —
  the app-side check in :func:`_reject_cross_origin` is the SOLE enforcement of
  security-checklist MUST #9.
* ``expected_origin`` — ``str`` = exact match, ``list`` = exact-member match.
"""

import json
from dataclasses import dataclass, field

import cbor2
import frappe
import webauthn
from frappe import _
from frappe.utils import cint
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
	InvalidAuthenticationResponse,
	InvalidBackupFlags,
	InvalidRegistrationResponse,
	WebAuthnException,
)
from webauthn.helpers.structs import (
	AttestationConveyancePreference,
	AuthenticatorSelectionCriteria,
	AuthenticatorTransport,
	PublicKeyCredentialDescriptor,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)

from passkeys import policy

# COSE algorithm preference order (fixed policy): EdDSA, ES256, RS256.
SUPPORTED_ALGS = (
	COSEAlgorithmIdentifier.EDDSA,
	COSEAlgorithmIdentifier.ECDSA_SHA_256,
	COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
)
SUPPORTED_ALG_IDS = frozenset(int(a) for a in SUPPORTED_ALGS)

# L3 §15.1 default; py_webauthn's 60 s is too short for hybrid (phone) users.
DEFAULT_TIMEOUT_MS = 300000

# WebAuthn spec cap on credential id length.
MAX_CREDENTIAL_ID_BYTES = 1023


class PasskeyVerificationError(frappe.AuthenticationError):
	"""Base for every engine rejection (a 401). The subclasses let tests assert which check
	fired; the login endpoints collapse them to one uniform wire type."""


class InvalidClientData(PasskeyVerificationError):
	"""App-side crossOrigin/topOrigin rejection — the SOLE enforcement of
	checklist MUST #9 (py_webauthn accepts both)."""


class RegistrationVerificationFailed(PasskeyVerificationError):
	"""Wraps py_webauthn ``InvalidRegistrationResponse`` (rpIdHash / origin /
	challenge / type / UP / UV rejections)."""


class AuthenticationVerificationFailed(PasskeyVerificationError):
	"""Wraps py_webauthn ``InvalidAuthenticationResponse`` (rpIdHash / origin /
	challenge / type / UP / UV / bad-signature — incl. credential substitution)."""


class BackupFlagViolation(PasskeyVerificationError):
	"""BS-without-BE (library ``InvalidBackupFlags``, own branch) or a
	write-once BE mutation on assertion."""


class SignCounterViolation(PasskeyVerificationError):
	"""Replay (equal nonzero counter — always) or a regression under the
	``passkey_sign_count_hard_fail`` knob."""


class UnsupportedAlgorithm(PasskeyVerificationError):
	"""The credential's COSE algorithm is outside the offered set."""


class CredentialTooLong(PasskeyVerificationError):
	"""Credential id exceeds the WebAuthn 1023-byte cap."""


@dataclass
class RegistrationResult:
	credential_id: str  # base64url
	public_key: str  # base64url COSE bytes — stored verbatim
	alg: int  # authoritative COSE alg from the public key (not client-reported)
	sign_count: int
	user_verified: bool
	backup_eligible: bool  # BE — write-once from here on
	backup_state: bool  # BS
	device_type: str  # "single_device" | "multi_device"
	transports: list = field(default_factory=list)  # verbatim, unknown values kept
	aaguid: str = ""
	fmt: str = ""
	attestation_object: str = ""  # base64url
	client_data_json: str = ""  # base64url
	authenticator_attachment: str | None = None
	credprops_rk: bool | None = None
	discoverable: str = "Unknown"  # tri-state from credProps.rk


@dataclass
class AuthenticationResult:
	credential_id: str  # base64url
	new_sign_count: int  # from the assertion's authenticatorData
	sign_count_to_store: int  # upward-only — never below the stored value
	sign_count_regression: bool  # flagged; login proceeds unless hard-fail
	user_verified: bool
	backup_eligible: bool  # asserted BE (derived from device type)
	backup_state: bool  # BS — refreshed on every success
	device_type: str
	user_handle: str | None  # base64url, from the raw response.userHandle


def _reject_cross_origin(credential: dict) -> None:
	"""Reject ``crossOrigin: true`` or any ``topOrigin`` member, parsed from the
	raw clientDataJSON. py_webauthn 2.8 copies crossOrigin but never reads it,
	and never parses topOrigin — so this is the only place the RP's
	"no cross-origin iframe ceremonies" policy is enforced."""
	try:
		raw = credential["response"]["clientDataJSON"]
		data = json.loads(base64url_to_bytes(raw))
	except (KeyError, TypeError, ValueError) as exc:
		raise InvalidClientData(_("Malformed client data.")) from exc
	if not isinstance(data, dict):
		raise InvalidClientData(_("Malformed client data."))
	if data.get("crossOrigin") is True:
		raise InvalidClientData(_("Cross-origin passkey ceremonies are not allowed."))
	if "topOrigin" in data:
		raise InvalidClientData(_("Cross-origin passkey ceremonies are not allowed."))


def _cose_alg(public_key_bytes: bytes) -> int:
	"""Authoritative COSE algorithm (label 3) from the credential public key —
	never the client-reported ``publicKeyAlgorithm`` (a hostile client can lie)."""
	return int(cbor2.loads(public_key_bytes)[3])


def verify_registration(
	*,
	credential: dict,
	expected_challenge,
	expected_rp_id: str,
	expected_origin,
	require_user_presence: bool = True,
	require_user_verification: bool = False,
) -> RegistrationResult:
	"""Verify a registration response and extract everything the credential row
	stores. ``require_user_presence`` is waived for conditional-create (keyed to
	the SERVER-stored flow, never client input); ``require_user_verification``
	is enforced app-side, so ceremonies pass ``False`` and layer the UV
	matrix on the returned ``user_verified`` bit."""
	_reject_cross_origin(credential)
	try:
		verified = webauthn.verify_registration_response(
			credential=json.dumps(credential),
			expected_challenge=base64url_to_bytes(expected_challenge),
			expected_rp_id=expected_rp_id,
			expected_origin=expected_origin,
			require_user_presence=require_user_presence,
			require_user_verification=require_user_verification,
			supported_pub_key_algs=list(SUPPORTED_ALGS),
		)
	except InvalidBackupFlags as exc:  # sibling exception — MUST be its own branch
		raise BackupFlagViolation(_("Impossible passkey backup state.")) from exc
	except (InvalidRegistrationResponse, WebAuthnException) as exc:
		raise RegistrationVerificationFailed(_("Passkey registration could not be verified.")) from exc

	public_key = verified.credential_public_key
	credential_id_bytes = verified.credential_id
	if len(credential_id_bytes) > MAX_CREDENTIAL_ID_BYTES:
		raise CredentialTooLong(_("Passkey credential id is too long."))

	alg = _cose_alg(public_key)
	if alg not in SUPPORTED_ALG_IDS:
		raise UnsupportedAlgorithm(_("Unsupported passkey algorithm."))

	response = credential.get("response", {})
	device_type = _enum_value(verified.credential_device_type)
	rk = _credprops_rk(credential)

	return RegistrationResult(
		credential_id=bytes_to_base64url(credential_id_bytes),
		public_key=bytes_to_base64url(public_key),
		alg=alg,
		sign_count=int(verified.sign_count),
		user_verified=bool(verified.user_verified),
		backup_eligible=(device_type == "multi_device"),
		backup_state=bool(verified.credential_backed_up),
		device_type=device_type,
		transports=list(response.get("transports") or []),
		aaguid=str(verified.aaguid or ""),
		fmt=_enum_value(verified.fmt),
		attestation_object=bytes_to_base64url(verified.attestation_object),
		client_data_json=response.get("clientDataJSON", ""),
		authenticator_attachment=credential.get("authenticatorAttachment"),
		credprops_rk=rk,
		discoverable=_discoverable(rk),
	)


def verify_authentication(
	*,
	credential: dict,
	expected_challenge,
	expected_rp_id: str,
	expected_origin,
	credential_public_key: str,
	stored_sign_count: int,
	stored_backup_eligible: bool | None = None,
	require_user_verification: bool = False,
	sign_count_hard_fail: bool = False,
) -> AuthenticationResult:
	"""Verify an assertion against a **stored** credential record.

	The library counter check is disabled (``credential_current_sign_count=0``);
	the policy is applied app-side against ``stored_sign_count`` — replay
	(equal nonzero) always rejects; a regression rejects only under
	``sign_count_hard_fail``, otherwise it is flagged and login proceeds.
	``stored_backup_eligible`` (when not ``None``) enables the write-once
	BE-mutation check."""
	_reject_cross_origin(credential)
	try:
		verified = webauthn.verify_authentication_response(
			credential=json.dumps(credential),
			expected_challenge=base64url_to_bytes(expected_challenge),
			expected_rp_id=expected_rp_id,
			expected_origin=expected_origin,
			credential_public_key=base64url_to_bytes(credential_public_key),
			credential_current_sign_count=0,  # disable the library counter check
			require_user_verification=require_user_verification,
		)
	except InvalidBackupFlags as exc:  # sibling exception — own branch
		raise BackupFlagViolation(_("Impossible passkey backup state.")) from exc
	except (InvalidAuthenticationResponse, WebAuthnException) as exc:
		raise AuthenticationVerificationFailed(_("Passkey could not be verified.")) from exc

	device_type = _enum_value(verified.credential_device_type)
	asserted_be = device_type == "multi_device"
	if stored_backup_eligible is not None and policy.backup_eligibility_mutated(
		stored_backup_eligible, asserted_be
	):
		raise BackupFlagViolation(_("Passkey backup eligibility changed — the credential is refused."))

	new_count = int(verified.new_sign_count)
	klass = policy.classify_sign_count(stored_sign_count, new_count)
	regression = False
	if klass == policy.SIGN_COUNT_REPLAY:
		raise SignCounterViolation(_("Passkey signature counter replay detected."))
	if klass == policy.SIGN_COUNT_REGRESSION:
		regression = True
		if sign_count_hard_fail:
			raise SignCounterViolation(_("Passkey signature counter regressed."))

	response = credential.get("response", {})
	return AuthenticationResult(
		credential_id=bytes_to_base64url(verified.credential_id),
		new_sign_count=new_count,
		sign_count_to_store=policy.sign_count_to_store(stored_sign_count, new_count),
		sign_count_regression=regression,
		user_verified=bool(verified.user_verified),
		backup_eligible=asserted_be,
		backup_state=bool(verified.credential_backed_up),
		device_type=device_type,
		user_handle=response.get("userHandle"),
	)


def verify_stored_assertion(credential: dict, record: dict, stored, *, sign_count_hard_fail: bool):
	"""Verify an assertion against a ceremony ``record`` and a locked credential row. UV
	is never required here; each ceremony layers its own UV policy on the result."""
	return verify_authentication(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		credential_public_key=stored.public_key,
		stored_sign_count=cint(stored.sign_count),
		stored_backup_eligible=bool(cint(stored.backup_eligible)),
		sign_count_hard_fail=sign_count_hard_fail,
	)


# ``options_to_json`` emits no ``extensions`` on 2.8; the client adds ``credProps``.


def build_registration_options(
	*,
	rp_id: str,
	rp_name: str,
	user_id: bytes,
	user_name: str,
	user_display_name: str,
	exclude_credentials: list,
	resident_key: str,
) -> tuple[dict, str]:
	"""Returns ``(options_json_dict, challenge_b64)``. ``authenticatorAttachment``
	is never set (hybrid stays alive)."""
	options = webauthn.generate_registration_options(
		rp_id=rp_id,
		rp_name=rp_name,
		user_id=user_id,
		user_name=user_name,
		user_display_name=user_display_name,
		timeout=DEFAULT_TIMEOUT_MS,
		attestation=AttestationConveyancePreference.NONE,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement(resident_key),
			user_verification=UserVerificationRequirement.PREFERRED,
		),
		exclude_credentials=_descriptors(exclude_credentials),
		supported_pub_key_algs=list(SUPPORTED_ALGS),
	)
	return json.loads(options_to_json(options)), bytes_to_base64url(options.challenge)


def build_authentication_options(
	*,
	rp_id: str,
	allow_credentials: list | None = None,
	user_verification: str = "preferred",
	timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> tuple[dict, str]:
	"""Returns ``(options_json_dict, challenge_b64)`` for a first/second-factor
	or confirmation ceremony."""
	options = webauthn.generate_authentication_options(
		rp_id=rp_id,
		timeout=timeout_ms,
		allow_credentials=_descriptors(allow_credentials or []),
		user_verification=UserVerificationRequirement(user_verification),
	)
	return json.loads(options_to_json(options)), bytes_to_base64url(options.challenge)


def _descriptors(entries: list) -> list:
	return [
		PublicKeyCredentialDescriptor(
			id=base64url_to_bytes(entry["id"]), transports=_known_transports(entry.get("transports"))
		)
		for entry in entries
	]


def _known_transports(transports) -> list | None:
	"""Transport hints the library knows; unknown values stay on the row, not the wire."""
	if not transports:
		return None
	known = []
	for value in transports:
		try:
			known.append(AuthenticatorTransport(value))
		except ValueError:
			continue
	return known or None


def _credprops_rk(credential: dict) -> bool | None:
	"""``credProps.rk`` from the raw credential JSON (py_webauthn drops
	``clientExtensionResults``); any non-object level reads as unknown."""
	exts = credential.get("clientExtensionResults")
	props = exts.get("credProps") if isinstance(exts, dict) else None
	rk = props.get("rk") if isinstance(props, dict) else None
	return rk if isinstance(rk, bool) else None


def _discoverable(rk: bool | None) -> str:
	if rk is True:
		return "Yes"
	if rk is False:
		return "No"
	return "Unknown"  # Safari ships no credProps — a real, permanent state


def _enum_value(value) -> str:
	return str(getattr(value, "value", value) or "")
