# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""J2 — the browserless WebAuthn TEST MODE (:mod:`passkeys.tests.fake_webauthn`).

Proves the fake-service round-trip runs through the REAL verify paths (a full
register → login → delete without a browser), that verification is genuinely on
(a tampered assertion is rejected — there is no skip-verification door), and that
the guard + the enable-time HTTPS relaxation behave exactly as the security musts
require."""

from contextlib import contextmanager
from unittest.mock import patch

import frappe
from frappe.auth import CookieManager
from frappe.utils import set_request

from passkeys import engine, passkey, state
from passkeys.tests import fake_webauthn, ui_test_helpers
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
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
		# The round-trip tests delete the sole credential of a password-capable user; a
		# disable_user_pass_login=1 left by an earlier module — committed, or merely cached
		# on frappe.local.system_settings (which the runner's rollback does not clear) —
		# would trip the last-credential guard here. Arrange AND cache-bust a clean
		# login-policy baseline so the test never depends on leaked global state.
		self._ss_disable = frappe.db.get_single_value("System Settings", "disable_user_pass_login")
		self._set_disable_user_pass_login(0)

	def _set_disable_user_pass_login(self, value):
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", value)
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None  # bust the request-local singles cache

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
		flush_settings_cache()
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		self._set_disable_user_pass_login(self._ss_disable)
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
		with self.assertRaises(engine.AuthenticationVerificationFailed):
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
		flush_settings_cache()

		# the test-mode path writes it directly, and the ceremony verifies against it
		report = fake_webauthn.round_trip(rp_id=rp_id, origin=origin)
		self.assertTrue(report["session_matches"])
		self.assertTrue(report["credential_gone"])

	# ---- explicit test-site guard --------------------------------------------

	def test_guard_refuses_a_non_system_manager(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		frappe.set_user(user)
		self.addCleanup(frappe.set_user, "Administrator")
		# v15's frappe.only_for is a no-op while flags.in_test is set (v16+ dropped
		# that short-circuit), so exercise the role gate outside test mode with both
		# site flags otherwise valid.
		with self._outside_test_mode(developer_mode=1, allow_tests=1):
			for guard in (fake_webauthn._guard, ui_test_helpers._guard):
				with self.subTest(module=guard.__module__):
					with self.assertRaises(frappe.PermissionError):
						guard()

	def test_guards_reject_when_both_site_flags_are_disabled(self):
		with self._outside_test_mode(developer_mode=0, allow_tests=0):
			for guard in (fake_webauthn._guard, ui_test_helpers._guard):
				with self.subTest(module=guard.__module__):
					with self.assertRaisesRegex(
						frappe.ValidationError, "both developer_mode and allow_tests"
					):
						guard()

	def test_guards_reject_developer_mode_without_allow_tests(self):
		with self._outside_test_mode(developer_mode=1, allow_tests=0):
			for guard in (fake_webauthn._guard, ui_test_helpers._guard):
				with self.subTest(module=guard.__module__):
					with self.assertRaisesRegex(
						frappe.ValidationError, "both developer_mode and allow_tests"
					):
						guard()

	def test_guards_reject_allow_tests_without_developer_mode(self):
		with self._outside_test_mode(developer_mode=0, allow_tests=1):
			for guard in (fake_webauthn._guard, ui_test_helpers._guard):
				with self.subTest(module=guard.__module__):
					with self.assertRaisesRegex(
						frappe.ValidationError, "both developer_mode and allow_tests"
					):
						guard()

	def test_guards_accept_developer_mode_with_allow_tests(self):
		with self._outside_test_mode(developer_mode=1, allow_tests=1):
			fake_webauthn._guard()
			ui_test_helpers._guard()

	def test_all_test_helper_whitelists_are_post_only(self):
		# slow_guest_echo is the ONE deliberate exception: sid_reseed_race.cy.js
		# must fire it as a Guest AND as a GET — an authenticated POST straggler
		# is CSRF-rejected before it reaches the handler, and the race it pins is
		# precisely a late-arriving cross-auth-state response. It is safe despite
		# that: flag-gated (see test_slow_guest_echo_is_flag_gated), a capped
		# no-op with no side effects, exposing nothing beyond the caller's own
		# session user. clear_all_test_sessions is also guest-callable (the
		# caller has just cleared its cookies) but stays POST-only, so it is NOT
		# an exception here; its safety is the same flag gate + a body that can
		# only log users out. EVERY other test helper must stay POST-only +
		# admin-only. This asserts that invariant structurally (the set of
		# non-POST-only helpers is exactly the documented exceptions) so it
		# neither rots on a magic count nor silently admits a new guest/GET
		# helper.
		documented_exceptions = {ui_test_helpers.slow_guest_echo}
		helpers = {
			fn
			for module in (fake_webauthn, ui_test_helpers)
			for fn in vars(module).values()
			if callable(fn) and fn in frappe.whitelisted
		}
		non_post_only = {
			fn for fn in helpers if frappe.allowed_http_methods_for_whitelisted_func[fn] != ["POST"]
		}
		self.assertEqual(
			non_post_only,
			documented_exceptions,
			"a test helper is not POST-only and is not a documented exception",
		)
		# Pin the GUEST axis too — it is the more dangerous one. Exactly two
		# helpers may be guest-callable: slow_guest_echo (the race pin) and
		# clear_all_test_sessions (the server half of test isolation; its
		# caller has just cleared its cookies). Any new allow_guest helper must
		# be documented here or this fails.
		documented_guest_exceptions = {
			ui_test_helpers.slow_guest_echo,
			ui_test_helpers.clear_all_test_sessions,
		}
		guest_helpers = {fn for fn in helpers if fn in frappe.guest_methods}
		self.assertEqual(
			guest_helpers,
			documented_guest_exceptions,
			"a test helper is guest-callable and is not a documented exception",
		)

	def test_slow_guest_echo_is_flag_gated(self):
		# The one guest-callable helper must be inert on any site that lacks the
		# deterministic-cookie flag (and lacks developer_mode+allow_tests), so it
		# can never be a guest-reachable stall primitive off the test bench.
		with patch.dict(
			frappe.conf,
			{"passkeys_deterministic_test_cookies": 0, "developer_mode": 0, "allow_tests": 0},
		):
			with self.assertRaisesRegex(frappe.ValidationError, "passkeys_deterministic_test_cookies"):
				ui_test_helpers.slow_guest_echo(delay=0)

	def test_clear_all_test_sessions_is_flag_gated(self):
		# The session-wipe helper is guest-callable; off a flagged test site it
		# must refuse, so a production site can never be mass-logged-out by a
		# guest POST. The STRING "0" case is load-bearing: `set-config <flag> 0`
		# without --parse stores a string, and a bare-truthy gate would keep the
		# endpoint enabled while the operator believes the flag is off.
		for off in (0, "0"):
			with self.subTest(flag=off):
				with patch.dict(
					frappe.conf,
					{"passkeys_deterministic_test_cookies": off, "developer_mode": off, "allow_tests": off},
				):
					with self.assertRaisesRegex(
						frappe.ValidationError, "passkeys_deterministic_test_cookies"
					):
						ui_test_helpers.clear_all_test_sessions()

	def test_clear_all_test_sessions_wipes_db_and_cache(self):
		# A live server session must be dead in BOTH stores after the wipe —
		# resolution reads the cache first (frappe/sessions.py), so a cache
		# survivor would keep authenticating /login visits.
		sid = frappe.generate_hash()
		Sessions = frappe.qb.DocType("Sessions")
		(
			frappe.qb.into(Sessions)
			.columns(Sessions.sid, Sessions.user, Sessions.sessiondata, Sessions.lastupdate, Sessions.status)
			.insert((sid, "Administrator", "{}", frappe.utils.now(), "Active"))
		).run()
		frappe.cache.hset("session", sid, {"user": "Administrator", "data": {"user": "Administrator"}})
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(frappe.cache.hdel, "session", sid)
		with patch.dict(frappe.conf, {"passkeys_deterministic_test_cookies": 1}):
			out = ui_test_helpers.clear_all_test_sessions()
		self.assertEqual(out["remaining"], 0)
		self.assertIsNone(frappe.cache.hget("session", sid))
		self.assertFalse(frappe.qb.from_(Sessions).select(Sessions.sid).where(Sessions.sid == sid).run())

	def test_confirmation_probes_run_test_guard_before_confirmation(self):
		probes = (
			ui_test_helpers.confirm_probe,
			ui_test_helpers.confirm_probe_passkey_only,
			ui_test_helpers.confirm_probe_failing,
		)
		with self._outside_test_mode(developer_mode=1, allow_tests=0):
			for probe in probes:
				with self.subTest(probe=probe.__name__):
					with self.assertRaisesRegex(
						frappe.ValidationError, "both developer_mode and allow_tests"
					):
						probe(token="guard-first")

	@contextmanager
	def _outside_test_mode(self, *, developer_mode: int, allow_tests: int):
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.flags.in_test = False
		try:
			with patch.dict(
				frappe.conf,
				{"developer_mode": developer_mode, "allow_tests": allow_tests},
			):
				yield
		finally:
			frappe.flags.in_test = saved_in_test
