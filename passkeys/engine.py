# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""WebAuthn engine — py_webauthn options/verify wrappers + app-side policy
(DESIGN-v1 §3; folds into ``frappe/passkey.py``).

This is the crypto core. It is imported **lazily inside ceremony endpoint
bodies only** (§1.3 hook-path import discipline): a broken ``webauthn`` /
``cryptography`` wheel must never take down the ``on_login`` / boot chains, so
the top-level ``import webauthn`` lives here and nowhere a hook can reach.

Normative py_webauthn (>=2.8,<3) behaviors honored here (proven, not
re-derived — ``spikes/webauthn-fixtures/README.md`` + ``PROBE-pywebauthn.md``):

* ``verify_authentication_response`` hard-rejects sign-count regressions
  *internally*; we pass ``credential_current_sign_count=0`` to disable that and
  enforce the §3.6 log+flag policy app-side.
* ``InvalidBackupFlags`` is a **sibling** exception (not a subclass) — its own
  ``except`` branch, else a naive handler turns a 401 into a 500.
* ``clientExtensionResults`` is dropped at parse — credProps is read from the
  **raw** credential JSON.
* ``crossOrigin`` is accepted by the library and ``topOrigin`` is never parsed —
  the app-side check in :func:`_reject_cross_origin` is the SOLE enforcement of
  security-checklist MUST #9 (§13 #9).
* ``expected_origin`` — ``str`` = exact match, ``list`` = exact-member match.
"""

import json
from dataclasses import dataclass, field

import cbor2
import frappe
import webauthn
from frappe import _
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

# COSE algorithm preference order (§9.1 fixed policy): EdDSA, ES256, RS256.
SUPPORTED_ALGS = (
	COSEAlgorithmIdentifier.EDDSA,
	COSEAlgorithmIdentifier.ECDSA_SHA_256,
	COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
)
SUPPORTED_ALG_IDS = frozenset(int(a) for a in SUPPORTED_ALGS)

# L3 §15.1 default; py_webauthn's own 60 s default is explicitly overridden
# (phone-fetching hybrid users exceed short timeouts — §5.4).
DEFAULT_TIMEOUT_MS = 300000

# WebAuthn spec cap on credential id length (§2.1 / §3.2).
MAX_CREDENTIAL_ID_BYTES = 1023


# ---------------------------------------------------------------------------
# Engine exception taxonomy (§3.0). Every verification failure is a
# ``frappe.AuthenticationError`` subclass ⇒ uniform 401 at the wire; the
# distinct classes let the test battery assert *which* security reason fired.
# The endpoint layer maps all of these to the uniform, non-enumerating 401
# (only the three guest-surface types in ``passkeys.passkey`` — CeremonyExpired
# / UnknownCredential / UVSetupRequired — carry a typed wire label).
# ---------------------------------------------------------------------------


class PasskeyVerificationError(frappe.AuthenticationError):
	"""Base for every engine-side ceremony rejection (§3.0)."""


class InvalidClientData(PasskeyVerificationError):
	"""App-side crossOrigin/topOrigin rejection — the SOLE enforcement of
	checklist MUST #9 (py_webauthn accepts both; §13 #9)."""


class RegistrationVerificationFailed(PasskeyVerificationError):
	"""Wraps py_webauthn ``InvalidRegistrationResponse`` (rpIdHash / origin /
	challenge / type / UP / UV rejections)."""


class AuthenticationVerificationFailed(PasskeyVerificationError):
	"""Wraps py_webauthn ``InvalidAuthenticationResponse`` (rpIdHash / origin /
	challenge / type / UP / UV / bad-signature — incl. credential substitution)."""


class BackupFlagViolation(PasskeyVerificationError):
	"""BS-without-BE (library ``InvalidBackupFlags``, own branch) or a
	write-once BE mutation on assertion (§3.6)."""


class SignCounterViolation(PasskeyVerificationError):
	"""Replay (equal nonzero counter — always) or a regression under the
	``passkey_sign_count_hard_fail`` knob (§3.6)."""


class UnsupportedAlgorithm(PasskeyVerificationError):
	"""The credential's COSE algorithm is outside the offered set (§3.2)."""


class CredentialTooLong(PasskeyVerificationError):
	"""Credential id exceeds the WebAuthn 1023-byte cap (§3.2)."""


# ---------------------------------------------------------------------------
# Verified-result value objects (what the endpoints persist / act on)
# ---------------------------------------------------------------------------


@dataclass
class RegistrationResult:
	credential_id: str  # base64url
	public_key: str  # base64url COSE bytes — stored verbatim (§2.1)
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
	discoverable: str = "Unknown"  # tri-state from credProps.rk (§3.5)


@dataclass
class AuthenticationResult:
	credential_id: str  # base64url
	new_sign_count: int  # from the assertion's authenticatorData
	sign_count_to_store: int  # upward-only (§3.6) — never below the stored value
	sign_count_regression: bool  # flagged; login proceeds unless hard-fail
	user_verified: bool
	backup_eligible: bool  # asserted BE (derived from device type)
	backup_state: bool  # BS — refreshed on every success
	device_type: str
	user_handle: str | None  # base64url, from the raw response.userHandle


# ---------------------------------------------------------------------------
# App-side clientDataJSON check (§3.1 step 5 / §13 #9)
# ---------------------------------------------------------------------------


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
	if data.get("crossOrigin") is True:
		raise InvalidClientData(_("Cross-origin passkey ceremonies are not allowed."))
	if "topOrigin" in data:
		raise InvalidClientData(_("Cross-origin passkey ceremonies are not allowed."))


def _as_challenge_bytes(challenge) -> bytes:
	return challenge if isinstance(challenge, bytes) else base64url_to_bytes(challenge)


def _cose_alg(public_key_bytes: bytes) -> int:
	"""Authoritative COSE algorithm (label 3) from the credential public key —
	never the client-reported ``publicKeyAlgorithm`` (a hostile client can lie)."""
	return int(cbor2.loads(public_key_bytes)[3])


# ---------------------------------------------------------------------------
# Verification — registration (§3.2)
# ---------------------------------------------------------------------------


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
	the SERVER-stored flow, never client input — §3.2); ``require_user_verification``
	is enforced app-side per §3.7, so ceremonies pass ``False`` and layer the UV
	matrix on the returned ``user_verified`` bit."""
	_reject_cross_origin(credential)
	try:
		verified = webauthn.verify_registration_response(
			credential=json.dumps(credential),
			expected_challenge=_as_challenge_bytes(expected_challenge),
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


# ---------------------------------------------------------------------------
# Verification — authentication (§3.1 / §3.6). Shared by first-factor login,
# second factor, and action confirmation (Phase 2b/3 consumers).
# ---------------------------------------------------------------------------


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
	the §3.6 policy is applied app-side against ``stored_sign_count`` — replay
	(equal nonzero) always rejects; a regression rejects only under
	``sign_count_hard_fail``, otherwise it is flagged and login proceeds.
	``stored_backup_eligible`` (when not ``None``) enables the write-once
	BE-mutation check (§3.6)."""
	_reject_cross_origin(credential)
	try:
		verified = webauthn.verify_authentication_response(
			credential=json.dumps(credential),
			expected_challenge=_as_challenge_bytes(expected_challenge),
			expected_rp_id=expected_rp_id,
			expected_origin=expected_origin,
			credential_public_key=base64url_to_bytes(credential_public_key),
			credential_current_sign_count=0,  # disable the library counter check (§3.1 step 7)
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


# ---------------------------------------------------------------------------
# Options construction (§3.2). ``options_to_json`` emits no ``extensions``
# member on 2.8, so the client injects ``{credProps:true}`` after parsing.
# ---------------------------------------------------------------------------


def build_registration_options(
	*,
	rp_id: str,
	rp_name: str,
	user_id: bytes,
	user_name: str,
	user_display_name: str,
	exclude_credentials: list | None = None,
	resident_key: str = "required",
	timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> tuple[dict, str]:
	"""Returns ``(options_json_dict, challenge_b64)``. ``authenticatorAttachment``
	is never set (hybrid stays alive, §5.4)."""
	options = webauthn.generate_registration_options(
		rp_id=rp_id,
		rp_name=rp_name,
		user_id=user_id,
		user_name=user_name,
		user_display_name=user_display_name,
		timeout=timeout_ms,
		attestation=AttestationConveyancePreference.NONE,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement(resident_key),
			user_verification=UserVerificationRequirement.PREFERRED,
		),
		exclude_credentials=_descriptors(exclude_credentials or []),
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
	or confirmation ceremony (consumed by Phase 2b/3)."""
	options = webauthn.generate_authentication_options(
		rp_id=rp_id,
		timeout=timeout_ms,
		allow_credentials=_descriptors(allow_credentials or []),
		user_verification=UserVerificationRequirement(user_verification),
	)
	return json.loads(options_to_json(options)), bytes_to_base64url(options.challenge)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _descriptors(entries: list) -> list:
	"""Build ``PublicKeyCredentialDescriptor`` list. Unknown transport strings
	(e.g. a future value) are dropped from the descriptor — they are hints only
	and are still stored verbatim on the credential row."""
	descriptors = []
	for entry in entries:
		descriptors.append(
			PublicKeyCredentialDescriptor(
				id=base64url_to_bytes(entry["id"]),
				transports=_known_transports(entry.get("transports")),
			)
		)
	return descriptors


def _known_transports(transports) -> list | None:
	if not transports:
		return None
	known = []
	for value in transports:
		try:
			known.append(AuthenticatorTransport(value))
		except ValueError:
			continue  # unknown hint — dropped from the descriptor, kept on the row
	return known or None


def _credprops_rk(credential: dict) -> bool | None:
	"""Read ``credProps.rk`` from the RAW credential JSON — py_webauthn drops
	``clientExtensionResults`` at parse, so this is the only source (§3.5). An
	explicit ``credProps: null`` (or a non-object at either level) is treated as
	unknown, never a 500 (C6): the ``.get`` default only substitutes for a MISSING
	key, so ``{"credProps": null}`` would surface ``None.get("rk")`` — guard each
	level with ``isinstance(..., dict)``."""
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
