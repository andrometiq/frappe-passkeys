# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Policy-matrix units (DESIGN-v1 §3.6/§3.7): the sign-count matrix incl. the
knob-off log+flag-proceed path (the vector gate runs hard-fail, so this is where
"regression completes the login" is pinned), BE mutation, the UV outcome table,
and per-flow residentKey."""

import secrets

from passkeys import engine, policy
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.soft_authenticator import SoftAuthenticator, b64url

RP_ID = "example.com"
ORIGIN = "https://example.com"


def _challenge() -> str:
	return b64url(secrets.token_bytes(32))


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
