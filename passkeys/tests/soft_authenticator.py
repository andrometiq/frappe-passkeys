# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Deterministic software authenticator — a test helper for **dynamic-challenge**
integration round-trips (the golden vectors are the static conformance anchor;
this complements them where the challenge is minted live by an endpoint, §12.1).

Not a test module. Kept ES256/Ed25519-only (RS256's embedded PEMs are unnecessary
here). Produces WebAuthn L3 JSON exactly as ``PublicKeyCredential.toJSON()`` would.
"""

import base64
import hashlib
import json
import struct

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

ES256 = -7
EDDSA = -8

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

AAGUID = b"\x00" * 16


def b64url(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sha256(data: bytes) -> bytes:
	return hashlib.sha256(data).digest()


class _Key:
	def __init__(self, alg: int, seed: bytes):
		self.alg = alg
		if alg == ES256:
			n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
			scalar = int.from_bytes(_sha256(b"ec|" + seed), "big") % (n - 1) + 1
			self.private_key = ec.derive_private_key(scalar, ec.SECP256R1())
		elif alg == EDDSA:
			self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(_sha256(b"ed|" + seed))
		else:
			raise ValueError(f"unsupported alg {alg}")

	def cose_public_key(self) -> bytes:
		pub = self.private_key.public_key()
		if self.alg == ES256:
			nums = pub.public_numbers()
			cose = {1: 2, 3: ES256, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
		else:
			raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
			cose = {1: 1, 3: EDDSA, -1: 6, -2: raw}
		return cbor2.dumps(cose, canonical=True)

	def spki_der(self) -> bytes:
		return self.private_key.public_key().public_bytes(
			serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
		)

	def sign(self, message: bytes) -> bytes:
		if self.alg == ES256:
			return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
		return self.private_key.sign(message)


def _flags(up, uv, be, bs, at) -> int:
	value = 0
	for on, bit in ((up, FLAG_UP), (uv, FLAG_UV), (be, FLAG_BE), (bs, FLAG_BS), (at, FLAG_AT)):
		if on:
			value |= bit
	return value


def _client_data(ceremony_type, challenge_b64, origin, cross_origin, top_origin) -> bytes:
	payload = {"type": ceremony_type, "challenge": challenge_b64, "origin": origin}
	if cross_origin is not None:
		payload["crossOrigin"] = cross_origin
	if top_origin is not None:
		payload["topOrigin"] = top_origin
	return json.dumps(payload, separators=(",", ":")).encode()


def _auth_data(rp_id, flags, sign_count, attested=None) -> bytes:
	data = _sha256(rp_id.encode()) + bytes([flags]) + struct.pack(">I", sign_count)
	if attested is not None:
		data += attested["aaguid"] + struct.pack(">H", len(attested["cred_id"]))
		data += attested["cred_id"] + attested["cose"]
	return data


class SoftAuthenticator:
	"""One deterministic credential."""

	def __init__(self, alg: int = ES256, seed: str = "primary"):
		self.alg = alg
		self.key = _Key(alg, seed.encode())
		self.credential_id = _sha256(f"cred|{alg}|{seed}".encode())[:32]
		self.user_handle = _sha256(f"uh|{seed}".encode())[:16]

	def registration(
		self,
		*,
		challenge_b64: str,
		rp_id: str,
		origin: str,
		up: bool = True,
		uv: bool = True,
		be: bool = False,
		bs: bool = False,
		sign_count: int = 0,
		cross_origin=False,
		top_origin=None,
		credprops_rk=None,
	) -> dict:
		client_data = _client_data("webauthn.create", challenge_b64, origin, cross_origin, top_origin)
		auth_data = _auth_data(
			rp_id,
			_flags(up, uv, be, bs, at=True),
			sign_count,
			attested={"aaguid": AAGUID, "cred_id": self.credential_id, "cose": self.key.cose_public_key()},
		)
		attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data}, canonical=True)
		ext = {"credProps": {"rk": credprops_rk}} if credprops_rk is not None else {}
		cred_id = b64url(self.credential_id)
		return {
			"id": cred_id,
			"rawId": cred_id,
			"response": {
				"clientDataJSON": b64url(client_data),
				"attestationObject": b64url(attestation),
				"transports": ["internal", "hybrid"],
				"publicKeyAlgorithm": self.alg,
				"publicKey": b64url(self.key.spki_der()),
				"authenticatorData": b64url(auth_data),
			},
			"authenticatorAttachment": "platform",
			"clientExtensionResults": ext,
			"type": "public-key",
		}

	def assertion(
		self,
		*,
		challenge_b64: str,
		rp_id: str,
		origin: str,
		up: bool = True,
		uv: bool = True,
		be: bool = False,
		bs: bool = False,
		sign_count: int = 1,
		include_user_handle: bool = True,
		cross_origin=False,
		top_origin=None,
	) -> dict:
		client_data = _client_data("webauthn.get", challenge_b64, origin, cross_origin, top_origin)
		auth_data = _auth_data(rp_id, _flags(up, uv, be, bs, at=False), sign_count)
		signature = self.key.sign(auth_data + _sha256(client_data))
		cred_id = b64url(self.credential_id)
		return {
			"id": cred_id,
			"rawId": cred_id,
			"response": {
				"clientDataJSON": b64url(client_data),
				"authenticatorData": b64url(auth_data),
				"signature": b64url(signature),
				"userHandle": b64url(self.user_handle) if include_user_handle else None,
			},
			"authenticatorAttachment": "platform",
			"clientExtensionResults": {},
			"type": "public-key",
		}
