# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""The golden-vector conformance gate (DESIGN-v1 §12.1). Drives the engine
verify path directly with the 35 committed deterministic vectors
(``spikes/webauthn-fixtures/vectors/``, schema in that dir's README):

* every POSITIVE vector must verify and extract the declared values;
* every NEGATIVE vector must be refused with an engine-typed error, and the
  app-side-only reasons (crossOrigin, BS-without-BE, sign-count) must be caught
  by the app's OWN check — not py_webauthn (which, for the crossOrigin cases,
  would accept the ceremony: ``library_expect: "pass"``).
"""

import json
from pathlib import Path

from passkeys import engine
from passkeys.tests.compat import IntegrationTestCase

VECTORS_DIR = Path(__file__).resolve().parents[2] / "spikes" / "webauthn-fixtures" / "vectors"


def _load() -> list:
	return [json.loads(p.read_text()) for p in sorted(VECTORS_DIR.glob("*.json"))]


def _run(vector: dict):
	ctx = vector["context"]
	if vector["kind"] == "registration":
		return engine.verify_registration(
			credential=vector["credential"],
			expected_challenge=ctx["expected_challenge"],
			expected_rp_id=ctx["expected_rp_id"],
			expected_origin=ctx["expected_origin"],
			require_user_presence=ctx.get("require_user_presence", True),
			require_user_verification=ctx.get("require_user_verification", False),
		)
	return engine.verify_authentication(
		credential=vector["credential"],
		expected_challenge=ctx["expected_challenge"],
		expected_rp_id=ctx["expected_rp_id"],
		expected_origin=ctx["expected_origin"],
		credential_public_key=ctx["credential_public_key"],
		stored_sign_count=ctx["credential_current_sign_count"],
		require_user_verification=ctx.get("require_user_verification", False),
		# The negative sign-count vectors (regression) must be REFUSED here; the
		# knob-off log+flag-proceed behavior is pinned separately (test_engine_policy).
		sign_count_hard_fail=True,
	)


# Which app-side (library-divergent or app-only) reason each negative must trip,
# so the gate proves the app check — not py_webauthn — is the enforcer.
APP_SIDE_REASON = {
	"reg-crossorigin-true": engine.InvalidClientData,
	"reg-crossorigin-true-toporigin": engine.InvalidClientData,
	"auth-crossorigin-true": engine.InvalidClientData,
	"auth-crossorigin-true-toporigin": engine.InvalidClientData,
	"reg-bs-without-be": engine.BackupFlagViolation,
	"auth-signcount-regression": engine.SignCounterViolation,
	"auth-signcount-equal": engine.SignCounterViolation,
}


class TestGoldenVectors(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.vectors = _load()

	def test_pack_is_complete(self):
		self.assertEqual(len(self.vectors), 35, "expected the committed 35-vector pack")
		positives = [v for v in self.vectors if v["expect"] == "pass"]
		negatives = [v for v in self.vectors if v["expect"] == "fail"]
		self.assertEqual(len(positives), 15)
		self.assertEqual(len(negatives), 20)

	def test_positive_vectors_verify_and_extract(self):
		passed = 0
		for vector in self.vectors:
			if vector["expect"] != "pass":
				continue
			with self.subTest(vector=vector["name"]):
				result = _run(vector)
				expected = vector["expected"]
				if vector["kind"] == "registration":
					self.assertEqual(result.credential_id, expected["credential_id"])
					self.assertEqual(result.public_key, expected["credential_public_key"])
					self.assertEqual(result.alg, expected["alg"])
					self.assertEqual(result.sign_count, expected["sign_count"])
					self.assertEqual(result.device_type, expected["credential_device_type"])
					self.assertEqual(result.backup_state, expected["credential_backed_up"])
					self.assertEqual(result.backup_eligible, expected["credential_device_type"] == "multi_device")
					if "credprops_rk" in expected:
						self.assertEqual(result.credprops_rk, expected["credprops_rk"])
						self.assertEqual(result.discoverable, "Yes" if expected["credprops_rk"] else "No")
				else:
					self.assertEqual(result.credential_id, expected["credential_id"])
					self.assertEqual(result.new_sign_count, expected["new_sign_count"])
					self.assertEqual(result.device_type, expected["credential_device_type"])
					self.assertEqual(result.backup_state, expected["credential_backed_up"])
					self.assertEqual(result.user_handle, expected["user_handle"])
				self.assertEqual(result.user_verified, expected["user_verified"])
				passed += 1
		self.assertEqual(passed, 15)

	def test_negative_vectors_are_refused(self):
		refused = 0
		for vector in self.vectors:
			if vector["expect"] != "fail":
				continue
			with self.subTest(vector=vector["name"]):
				expected_class = APP_SIDE_REASON.get(vector["name"], engine.PasskeyVerificationError)
				with self.assertRaises(expected_class):
					_run(vector)
				refused += 1
		self.assertEqual(refused, 20)

	def test_crossorigin_is_app_side_only(self):
		"""The four crossOrigin vectors declare ``library_expect: "pass"`` — prove
		py_webauthn WOULD accept them, so the app-side check is the sole gate."""
		import webauthn
		from webauthn.helpers import base64url_to_bytes

		divergent = [v for v in self.vectors if v.get("library_expect") == "pass"]
		self.assertEqual(len(divergent), 4)
		for vector in divergent:
			ctx = vector["context"]
			with self.subTest(vector=vector["name"]):
				# 1. app rejects
				with self.assertRaises(engine.InvalidClientData):
					_run(vector)
				# 2. the library does NOT (it accepts crossOrigin, never parses topOrigin)
				if vector["kind"] == "registration":
					webauthn.verify_registration_response(
						credential=json.dumps(vector["credential"]),
						expected_challenge=base64url_to_bytes(ctx["expected_challenge"]),
						expected_rp_id=ctx["expected_rp_id"],
						expected_origin=ctx["expected_origin"],
						require_user_presence=ctx.get("require_user_presence", True),
						require_user_verification=ctx.get("require_user_verification", False),
					)
				else:
					webauthn.verify_authentication_response(
						credential=json.dumps(vector["credential"]),
						expected_challenge=base64url_to_bytes(ctx["expected_challenge"]),
						expected_rp_id=ctx["expected_rp_id"],
						expected_origin=ctx["expected_origin"],
						credential_public_key=base64url_to_bytes(ctx["credential_public_key"]),
						credential_current_sign_count=0,
						require_user_verification=ctx.get("require_user_verification", False),
					)
