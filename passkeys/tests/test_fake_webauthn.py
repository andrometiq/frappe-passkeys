# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""J2 — the browserless WebAuthn TEST MODE (:mod:`passkeys.tests.fake_webauthn`).

Proves the fake-service round-trip runs through the REAL verify paths (a full
register → login → delete without a browser), that verification is genuinely on
(a tampered assertion is rejected — there is no skip-verification door), and that
the guard + the enable-time HTTPS relaxation behave exactly as the security musts
require."""

from unittest.mock import patch

import frappe
from frappe.auth import CookieManager
from frappe.utils import set_request

from passkeys import passkey, state
from passkeys.tests import fake_webauthn
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator, b64url, b64url_decode

_SETTINGS_FIELDS = (
	"login_with_passkey",
	"passkey_as_second_factor",
	"passkey_rp_id",
	"passkey_origins",
)


class FakeWebAuthnTestModeTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")

	def tearDown(self):
		# round_trip / verify_login mint a session via login_as, which COMMITS mid-test —
		# settings writes + any credential/handle/user rows then survive the runner's
		# rollback. Restore + sweep AFTER the rollback and commit so nothing leaks into the
		# bench or trips the global unique index on a later test.
		super().tearDown()
		frappe.set_user("Administrator")
		# Faithful restore (never `or 0` — that writes a literal "0" into the text rp/origin
		# fields, which this committing tearDown would then leak into the shared single).
		for field in _SETTINGS_FIELDS:
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field))
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	# ---- the deliverable: a full round-trip through the real verify paths ----

	def test_full_round_trip_register_login_delete(self):
		report = fake_webauthn.round_trip()
		# registration persisted a real row via the unmodified verifier
		self.assertTrue(report["registered"])
		# the discoverable login resolved the SAME user and minted its session
		self.assertTrue(report["session_matches"])
		self.assertEqual(report["logged_in_as"], report["user"])
		# the assertion's sign_count (5) advanced the stored counter — the real
		# verify_authentication ran, not a stub
		self.assertEqual(report["sign_count"], 5)
		# the sudo-gated delete removed it
		self.assertEqual(report["deleted"], report["registered"])
		self.assertTrue(report["credential_gone"])

	def test_round_trip_supports_ed25519(self):
		# The SoftAuthenticator covers ES256 + Ed25519; drive the whole pipeline on EdDSA.
		report = fake_webauthn.round_trip(alg=-8)
		self.assertTrue(report["session_matches"])
		self.assertTrue(report["credential_gone"])

	# ---- enroll as a standalone helper -----------------------------------

	def test_enroll_gives_a_user_a_passkey(self):
		# enrol for a named user from the System Manager session (the ceremony runs as the
		# target; the credential is committed, and the tearDown sweep reclaims it).
		fake_webauthn.enable()
		user = make_user()
		result = fake_webauthn.enroll(user=user, seed="standalone")
		self.assertTrue(frappe.db.exists("WebAuthn Credential", result["name"]))
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", result["name"], "user"), user)
		self.assertTrue(result["handle"])

	# ---- verification is REAL (must #3: no skip-verification door) -----------

	def test_tampered_assertion_is_rejected_by_the_real_verifier(self):
		"""A fake authenticator that signs the WRONG challenge is rejected by the
		unmodified verifier — the test mode adds no accept-anything path; it only
		generates spec-valid payloads. The credential resolves (handle aligned), so the
		ONLY reason this fails is genuine signature/challenge verification."""
		fake_webauthn.enable()
		user = make_user()
		reg = fake_webauthn.enroll(user=user, seed="tamper")
		auth = SoftAuthenticator(seed="tamper")
		auth.user_handle = b64url_decode(reg["handle"])

		frappe.set_user("Guest")
		ip = frappe.generate_hash(length=12)

		def _request(binder=None):
			headers = [("Cookie", f"{state.BINDER_COOKIE}={binder}")] if binder else None
			set_request(method="POST", path="/api/method/passkeys.passkey.begin_login", headers=headers)
			frappe.local.cookie_manager = CookieManager()
			frappe.local.request_ip = ip
			frappe.local.form_dict = frappe._dict()

		_request()
		begun = passkey.begin_login()
		set_cookie = frappe.local.cookie_manager.cookies.get(state.BINDER_COOKIE)
		binder = set_cookie["value"] if set_cookie else None
		# sign a DIFFERENT challenge than the one begin_login minted
		bogus_challenge = b64url(b"\x11" * 32)
		self.assertNotEqual(bogus_challenge, begun["options"]["challenge"])
		assertion = auth.assertion(
			challenge_b64=bogus_challenge,
			rp_id=fake_webauthn.DEFAULT_RP_ID,
			origin=fake_webauthn.DEFAULT_ORIGIN,
			sign_count=3,
		)

		_request(binder=binder)
		with self.assertRaises(Exception):
			passkey.verify_login(begun["state_id"], assertion)
		# no session was minted — verification genuinely gated the login
		self.assertEqual(frappe.session.user, "Guest")

	# ---- must #4: only the ENABLE-TIME https validator is relaxed ------------

	def test_enable_relaxes_only_the_enable_time_https_validator(self):
		"""``enable`` stores an ``http://*.localhost`` origin a normal ``.save()`` would
		refuse, and a full round-trip still verifies against it — proving the relaxation
		is enable-time only, with the ceremony-time origin check fully intact."""
		rp_id = "passkeys.localhost"
		origin = "http://passkeys.localhost:8000"

		# the real enable-time validator refuses this http origin (validator intact)
		doc = frappe.get_doc("Passkey Settings")
		doc.login_with_passkey = 1
		doc.passkey_rp_id = rp_id
		doc.passkey_origins = origin
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

		# the test-mode path writes it directly, and the ceremony verifies against it
		report = fake_webauthn.round_trip(rp_id=rp_id, origin=origin)
		self.assertTrue(report["session_matches"])
		self.assertTrue(report["credential_gone"])

	# ---- the guard (must #1): never callable in production -------------------

	def test_guard_refuses_a_non_system_manager(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		frappe.set_user(user)
		self.addCleanup(frappe.set_user, "Administrator")
		# v15's frappe.only_for is a no-op while flags.in_test is set (v16+ dropped
		# that short-circuit); clear it so the real System Manager gate is exercised.
		# only_for runs before the dev-bench check, so PermissionError still fires
		# first on a site without developer_mode.
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.flags.in_test = False
		try:
			with self.assertRaises(frappe.PermissionError):
				fake_webauthn.enable()
		finally:
			frappe.flags.in_test = saved_in_test

	def test_guard_refuses_off_a_developer_or_test_bench(self):
		# System Manager, but neither developer_mode nor in_test → hard refuse.
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.flags.in_test = False
		try:
			with patch.dict(frappe.conf, {"developer_mode": 0}):
				with self.assertRaises(frappe.ValidationError):
					fake_webauthn.enable()
		finally:
			frappe.flags.in_test = saved_in_test
