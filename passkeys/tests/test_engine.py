# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Engine verification suites: the policy-matrix units (sign-count matrix incl.
the knob-off log+flag-proceed path, BE mutation, the UV outcome table, per-flow
residentKey, app-origin membership) AND the golden-vector conformance gate that
drives the engine verify path with the 35 committed deterministic vectors
(``passkeys/tests/vectors/``, schema in that dir's README)."""

import json
import secrets
from pathlib import Path

import frappe

from passkeys import engine, policy
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.soft_authenticator import SoftAuthenticator, b64url

RP_ID = "example.com"
ORIGIN = "https://example.com"
VECTORS_DIR = Path(__file__).resolve().parent / "vectors"


def _challenge() -> str:
	return b64url(secrets.token_bytes(32))


def _load() -> list:
	return json.loads((VECTORS_DIR / "vectors.json").read_text())


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
		# knob-off log+flag-proceed behavior is pinned by TestSignCountPolicy below.
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


class TestSignCountPolicy(IntegrationTestCase):
	def test_classify_matrix(self):
		self.assertEqual(policy.classify_sign_count(0, 0), policy.SIGN_COUNT_UNCHANGED)
		self.assertEqual(policy.classify_sign_count(41, 42), policy.SIGN_COUNT_INCREMENT)
		self.assertEqual(policy.classify_sign_count(42, 42), policy.SIGN_COUNT_REPLAY)
		self.assertEqual(policy.classify_sign_count(10, 5), policy.SIGN_COUNT_REGRESSION)
		self.assertEqual(policy.classify_sign_count(10, 0), policy.SIGN_COUNT_REGRESSION)

	def test_counter_never_written_downward(self):
		self.assertEqual(policy.sign_count_to_store(10, 5), 10)
		self.assertEqual(policy.sign_count_to_store(10, 20), 20)
		self.assertEqual(policy.sign_count_to_store(0, 0), 0)

	def _assert_at(self, *, stored, asserted, hard_fail):
		auth = SoftAuthenticator()
		challenge = _challenge()
		return engine.verify_authentication(
			credential=auth.assertion(
				challenge_b64=challenge, rp_id=RP_ID, origin=ORIGIN, sign_count=asserted
			),
			expected_challenge=challenge,
			expected_rp_id=RP_ID,
			expected_origin=ORIGIN,
			credential_public_key=b64url(auth.key.cose_public_key()),
			stored_sign_count=stored,
			sign_count_hard_fail=hard_fail,
		)

	def test_regression_with_knob_off_completes(self):
		result = self._assert_at(stored=10, asserted=5, hard_fail=False)
		self.assertTrue(result.sign_count_regression)
		self.assertEqual(result.sign_count_to_store, 10)  # never downward

	def test_regression_with_knob_on_rejects(self):
		with self.assertRaises(engine.SignCounterViolation):
			self._assert_at(stored=10, asserted=5, hard_fail=True)

	def test_equal_nonzero_replay_always_rejects(self):
		with self.assertRaises(engine.SignCounterViolation):
			self._assert_at(stored=7, asserted=7, hard_fail=False)

	def test_increment_stores_new(self):
		result = self._assert_at(stored=41, asserted=42, hard_fail=True)
		self.assertFalse(result.sign_count_regression)
		self.assertEqual(result.sign_count_to_store, 42)


class TestBackupFlagPolicy(IntegrationTestCase):
	def _authenticate(self, *, stored_be, asserted_be):
		auth = SoftAuthenticator()
		challenge = _challenge()
		return engine.verify_authentication(
			credential=auth.assertion(
				challenge_b64=challenge, rp_id=RP_ID, origin=ORIGIN, be=asserted_be, bs=asserted_be
			),
			expected_challenge=challenge,
			expected_rp_id=RP_ID,
			expected_origin=ORIGIN,
			credential_public_key=b64url(auth.key.cose_public_key()),
			stored_sign_count=0,
			stored_backup_eligible=stored_be,
		)

	def test_be_mutation_rejected(self):
		with self.assertRaises(engine.BackupFlagViolation):
			self._authenticate(stored_be=False, asserted_be=True)

	def test_matching_be_passes(self):
		result = self._authenticate(stored_be=True, asserted_be=True)
		self.assertTrue(result.backup_eligible)
		self.assertEqual(result.device_type, "multi_device")

	def test_mutation_check_skipped_when_stored_unknown(self):
		auth = SoftAuthenticator()
		challenge = _challenge()
		result = engine.verify_authentication(
			credential=auth.assertion(challenge_b64=challenge, rp_id=RP_ID, origin=ORIGIN, be=True, bs=True),
			expected_challenge=challenge,
			expected_rp_id=RP_ID,
			expected_origin=ORIGIN,
			credential_public_key=b64url(auth.key.cose_public_key()),
			stored_sign_count=0,
			stored_backup_eligible=None,
		)
		self.assertTrue(result.backup_eligible)


class TestCredPropsExtraction(IntegrationTestCase):
	def test_credprops_null_is_unknown_not_500(self):
		"""C6: an explicit ``clientExtensionResults: {"credProps": null}`` must read
		as unknown (discoverable "Unknown"), never raise ``AttributeError`` → 500 —
		the ``.get`` default only substitutes for a MISSING key, not an explicit
		null. (Safari-style omission — ``{}`` — is the neighbouring already-handled
		case; this pins the explicit-null one.)"""
		auth = SoftAuthenticator()
		challenge = _challenge()
		credential = auth.registration(challenge_b64=challenge, rp_id=RP_ID, origin=ORIGIN)
		credential["clientExtensionResults"] = {"credProps": None}
		result = engine.verify_registration(
			credential=credential,
			expected_challenge=challenge,
			expected_rp_id=RP_ID,
			expected_origin=ORIGIN,
		)
		self.assertIsNone(result.credprops_rk)
		self.assertEqual(result.discoverable, "Unknown")


class TestUvPolicy(IntegrationTestCase):
	def test_passwordless_outcome_matrix(self):
		self.assertEqual(policy.passwordless_uv_outcome(True, True), policy.UV_SESSION)
		self.assertEqual(policy.passwordless_uv_outcome(True, False), policy.UV_SETUP)
		self.assertEqual(policy.passwordless_uv_outcome(False, True), policy.UV_REJECT)
		self.assertEqual(policy.passwordless_uv_outcome(False, False), policy.UV_REJECT)

	def test_wire_userverification_per_ceremony(self):
		self.assertEqual(policy.UV_WIRE["first_factor"], "preferred")
		self.assertEqual(policy.UV_WIRE["second_factor"], "discouraged")
		self.assertEqual(policy.UV_WIRE["confirmation"], "required")

	def test_resident_key_per_flow(self):
		self.assertEqual(policy.resident_key_for_flow("explicit"), "required")
		self.assertEqual(policy.resident_key_for_flow("conditional_create"), "preferred")


# A native Android app presents android:apk-key-hash:<43-char base64url SHA-256>.
VALID_APK_HASH = "i785YGGJMKRF89cJHnsbBQ-K_a8k6_HrLj0TiAn8eVk"
VALID_APP_ORIGIN = f"android:apk-key-hash:{VALID_APK_HASH}"


class TestAppOrigins(IntegrationTestCase):
	"""Trusted App Origins (native mobile): the app-origin carve-out is additive to
	the web ``expected_origin`` list and never weakens web-origin validation."""

	def test_valid_apk_hash_is_43_base64url_chars(self):
		import base64

		self.assertEqual(len(VALID_APK_HASH), 43)
		# decodes cleanly as unpadded base64url of a 32-byte SHA-256 digest
		self.assertEqual(len(base64.urlsafe_b64decode(VALID_APK_HASH + "=")), 32)

	def test_app_origins_trims_dedupes_and_skips_blanks(self):
		settings = frappe._dict({"passkey_app_origins": f"  {VALID_APP_ORIGIN}  \n\n{VALID_APP_ORIGIN}\n"})
		self.assertEqual(policy.app_origins(settings), [VALID_APP_ORIGIN])

	def test_app_origins_empty_when_unset(self):
		self.assertEqual(policy.app_origins(frappe._dict({})), [])

	def test_resolve_expected_origins_appends_app_after_web(self):
		settings = frappe._dict(
			{"passkey_origins": "https://app.example.com", "passkey_app_origins": VALID_APP_ORIGIN}
		)
		self.assertEqual(
			policy.resolve_expected_origins(settings, "example.com"),
			["https://example.com", "https://app.example.com", VALID_APP_ORIGIN],
		)

	def test_resolve_expected_origins_web_only_without_app_origins(self):
		self.assertEqual(
			policy.resolve_expected_origins(frappe._dict({}), "example.com"),
			["https://example.com"],
		)

	def test_resolve_origins_never_sees_app_origins(self):
		# The web resolver feeds validate_origins + the request-host pre-check + the
		# settings mirror; an app origin must never leak into it.
		settings = frappe._dict({"passkey_origins": "", "passkey_app_origins": VALID_APP_ORIGIN})
		self.assertEqual(policy.resolve_origins(settings, "example.com"), ["https://example.com"])

	def test_validate_app_origins_accepts_valid_and_empty(self):
		policy.validate_app_origins(frappe._dict({"passkey_app_origins": VALID_APP_ORIGIN}))
		policy.validate_app_origins(frappe._dict({"passkey_app_origins": ""}))
		policy.validate_app_origins(frappe._dict({}))  # no raise

	def test_validate_app_origins_rejects_web_url(self):
		with self.assertRaises(frappe.ValidationError):
			policy.validate_app_origins(frappe._dict({"passkey_app_origins": "https://example.com"}))

	def test_validate_app_origins_rejects_ios_style_entry(self):
		# iOS presents https://<rp_id> and must NOT be entered here.
		with self.assertRaises(frappe.ValidationError):
			policy.validate_app_origins(
				frappe._dict({"passkey_app_origins": "ios:bundle-id:com.example.app"})
			)

	def test_validate_app_origins_rejects_malformed_hash(self):
		for bad in (
			"android:apk-key-hash:tooshort",
			f"android:apk-key-hash:{VALID_APK_HASH}=",  # padding not allowed
			"android:apk-key-hash:" + "A" * 44,  # wrong length
			"android:apk-key-hash:" + "A" * 42,  # wrong length
			"android:apk-key-hash:" + "!" * 43,  # outside the base64url alphabet
		):
			with self.assertRaises(frappe.ValidationError):
				policy.validate_app_origins(frappe._dict({"passkey_app_origins": bad}))


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
					self.assertEqual(
						result.backup_eligible, expected["credential_device_type"] == "multi_device"
					)
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
