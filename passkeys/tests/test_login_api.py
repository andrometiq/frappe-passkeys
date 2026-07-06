# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""First-factor passwordless login round-trip on the live bench (DESIGN-v1 §3.1,
§3.4, §4.3, §12.2): register a discoverable UV credential → begin_login
(discoverable, no identifier) → verify_login mints a session for the resolved
user; the binder cookie is set-iff-absent with a sliding refresh and closes
login-CSRF; the UV outcome policy gates passwordless vs uv-setup; the sign
counter advances; the rate-limit path fires; the guest translations endpoint
serves app strings."""

from unittest.mock import patch

import frappe
from frappe.auth import CookieManager
from frappe.utils import set_request
from frappe.utils.password import update_password

from passkeys import passkey, state
from passkeys.api import registration
from passkeys.passkey import CeremonyExpired, UnknownCredential, UVSetupRequired
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator

RP_ID = "example.com"
ORIGIN = "https://example.com"
PWD = "Secret_passw0rd_9x!"


class LoginCeremonyTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_sign_count_hard_fail = 0
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self._ip = frappe.generate_hash(length=12)  # per-test rate-limit bucket
		self.addCleanup(self._restore)

	def tearDown(self):
		# verify_login / complete_uv_setup mint a session via login_as, which
		# COMMITS mid-test — credential/handle/user rows then survive the test
		# runner's rollback (super().tearDown()). Sweep them AFTER the rollback
		# and commit, so nothing leaks into the bench or trips the global unique
		# index on a later test/module (registration_api reuses seed "primary").
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()  # must survive past the runner's per-test rollback

	def _restore(self):
		frappe.set_user("Administrator")
		for field in (
			"login_with_passkey",
			"passkey_as_second_factor",
			"passkey_rp_id",
			"passkey_origins",
			"passkey_sign_count_hard_fail",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	# -- fixtures -----------------------------------------------------------

	def _user(self) -> str:
		user = make_user()
		update_password(user, PWD)
		return user  # cleanup is the committing tearDown sweep (login_as commits)

	def _enroll(self, user, seed="primary", uv=True):
		"""Register a discoverable credential through the real registration
		ceremony, then return (SoftAuthenticator, stored_handle_b64). The seed is
		made per-test-unique: ``login_as`` commits mid-test, so a deterministic
		credential id would leak across tests/modules and trip the global unique
		index (`credential_id_sha256`)."""
		frappe.set_user(user)
		state.set_sudo_window(frappe.session.sid, {"user": user, "seeded_by": "password"}, ttl=600)
		begun = registration.begin_registration(flow="explicit")
		auth = SoftAuthenticator(seed=f"{seed}-{self._ip}")
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"],
			rp_id=RP_ID,
			origin=ORIGIN,
			uv=uv,
			credprops_rk=True,
		)
		registration.verify_registration(begun["state_id"], credential)
		handle = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
		# drive the assertion's userHandle from the SERVER-stored handle bytes
		auth.user_handle = _b64url_decode(handle)
		frappe.set_user("Guest")
		return auth, handle

	# -- request harness (binder cookie + rate-limit isolation) -------------

	def _request(self, path, binder=None):
		headers = [("Cookie", f"{state.BINDER_COOKIE}={binder}")] if binder else None
		set_request(method="POST", path=path, headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = self._ip
		frappe.local.form_dict = frappe._dict()

	def _begin(self, binder=None):
		self._request("/api/method/passkeys.passkey.begin_login", binder=binder)
		result = passkey.begin_login()
		set_binder = frappe.local.cookie_manager.cookies.get(state.BINDER_COOKIE)
		return result, (set_binder["value"] if set_binder else None)

	def _verify(self, state_id, credential, binder):
		self._request("/api/method/passkeys.passkey.verify_login", binder=binder)
		return passkey.verify_login(state_id, credential)

	def _assert(self, auth, options, **kw):
		return auth.assertion(challenge_b64=options["challenge"], rp_id=RP_ID, origin=ORIGIN, **kw)

	# ======================================================================
	# full passwordless round-trip
	# ======================================================================

	def test_full_passwordless_round_trip_mints_session(self):
		user = self._user()
		auth, _handle = self._enroll(user)

		begun, binder = self._begin()
		self.assertTrue(begun["enabled"])
		self.assertTrue(begun["modes"]["first_factor"])
		self.assertIn("state_id", begun)
		self.assertEqual(begun["options"]["allowCredentials"], [])  # discoverable-only
		self.assertTrue(binder)

		credential = self._assert(auth, begun["options"], sign_count=5)
		self._verify(begun["state_id"], credential, binder)

		# session minted for the RESOLVED user (username-less login worked)
		self.assertEqual(frappe.session.user, user)
		# the CORE login envelope rode through: message is core's own copy
		# ("Logged In" for system users, "No App" for website users) and the
		# redirect target is the returned home_page — never a hardcoded /app|/desk
		self.assertIn(frappe.local.response.get("message"), ("Logged In", "No App"))
		self.assertTrue(frappe.local.response.get("home_page"))
		# sign counter advanced + last-used stamped
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "sign_count"), 5)

	def test_passkey_only_user_passwordless_round_trip_seeds_passkey_window(self):
		"""C1 regression: verify_login's SESSION leg sets
		``frappe.local.flags.passkey_login`` itself (F3-2) — driven through the
		REAL begin→verify path with the real on_login hook firing, no manual flag.
		Without the flag a ``passkey_only_login=1`` user trips their own §9.3 veto
		(total lockout from their only login method) and every passwordless
		session seeds a "weak" sudo window instead of "passkey" (§7.1)."""
		user = self._user()
		auth, _handle = self._enroll(user)
		frappe.db.set_value(
			"WebAuthn User Handle", {"user": user}, "passkey_only_login", 1, update_modified=False
		)
		# a flag leaked by an earlier test would false-pass this regression
		frappe.local.flags.pop("passkey_login", None)

		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], sign_count=5)
		self._verify(begun["state_id"], credential, binder)

		# the veto let the passkey leg through; the session minted for that user
		self.assertEqual(frappe.session.user, user)
		# ...and seed_sudo_window classified it as a full "passkey" window (§7.1)
		window = state.get_sudo_window(frappe.session.sid)
		self.assertEqual((window or {}).get("seeded_by"), "passkey")

	def test_begin_login_mode_off_is_pure_config_no_state(self):
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		begun, binder = self._begin()
		self.assertFalse(begun["enabled"])
		self.assertNotIn("state_id", begun)
		self.assertIsNone(binder)  # no cookie minted when mode off

	# ======================================================================
	# binder cookie (§4.3) — set-if-absent, sliding refresh, fail closed
	# ======================================================================

	def test_binder_set_if_absent_and_sliding_refresh(self):
		# first begin mints a binder; a second begin carrying it re-sends the
		# SAME value (set-iff-absent, not rotation) with a fresh Max-Age
		_b1, binder1 = self._begin()
		self.assertTrue(binder1)
		_b2, binder2 = self._begin(binder=binder1)
		self.assertEqual(binder1, binder2)
		self.assertEqual(
			frappe.local.cookie_manager.cookies[state.BINDER_COOKIE]["max_age"], state.BINDER_MAX_AGE
		)

	def test_absent_binder_fails_closed(self):
		user = self._user()
		auth, _ = self._enroll(user)
		begun, _binder = self._begin()
		credential = self._assert(auth, begun["options"])
		# verify with NO binder cookie on the request
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], credential, binder=None)

	def test_mismatched_binder_fails_closed(self):
		user = self._user()
		auth, _ = self._enroll(user)
		begun, _binder = self._begin()
		credential = self._assert(auth, begun["options"])
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], credential, binder=frappe.generate_hash())

	def test_login_csrf_attacker_ceremony_cannot_log_victim_in(self):
		"""The login-CSRF regression: an attacker who begins AND signs their own
		ceremony cannot complete it inside a victim's browser — the victim's
		request carries no (or a different) binder cookie. The attacker cannot
		set/read this HttpOnly cookie cross-site. Positive control: the same
		signed assertion + state succeeds WITH the binder, proving the binder is
		the sole closing control."""
		user = self._user()
		auth, _ = self._enroll(user)

		# attacker begins + signs their own real, valid ceremony
		begun, attacker_binder = self._begin()
		signed = self._assert(auth, begun["options"], sign_count=9)

		# carried into a victim browser (no attacker binder cookie) → refused
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], signed, binder=None)

		# positive control: identical assertion completes only WITH the binder.
		# (re-begin because the victim attempt consumed the single-use state)
		begun2, binder2 = self._begin(binder=attacker_binder)
		signed2 = self._assert(auth, begun2["options"], sign_count=10)
		self._verify(begun2["state_id"], signed2, binder=binder2)
		self.assertEqual(frappe.session.user, user)

	# ======================================================================
	# discoverable user resolution (§3.1 step 6)
	# ======================================================================

	def test_resolves_correct_user_from_credential(self):
		alice = self._user()
		auth_a, _ = self._enroll(alice, seed="alice")
		bob = self._user()
		self._enroll(bob, seed="bob")  # a second enrolled user in the table

		begun, binder = self._begin()
		credential = self._assert(auth_a, begun["options"])
		self._verify(begun["state_id"], credential, binder)
		self.assertEqual(frappe.session.user, alice)  # not bob

	def test_unknown_credential_typed_error(self):
		# an assertion from an authenticator that was never registered
		auth = SoftAuthenticator(seed="never-registered")
		auth.user_handle = b"\x01" * 16
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"])
		with self.assertRaises(UnknownCredential):
			self._verify(begun["state_id"], credential, binder)

	# ======================================================================
	# UV outcomes (§3.7) + uv-setup step-up (§3.4)
	# ======================================================================

	def test_uv_initialized_credential_gets_session(self):
		user = self._user()
		auth, _ = self._enroll(user, uv=True)
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True)
		self._verify(begun["state_id"], credential, binder)
		self.assertEqual(frappe.session.user, user)

	def test_no_uv_assertion_is_rejected(self):
		user = self._user()
		auth, _ = self._enroll(user, uv=True)
		begun, binder = self._begin()
		# a UV-less assertion never yields a passwordless session (§3.7)
		credential = self._assert(auth, begun["options"], uv=False)
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], credential, binder)
		self.assertEqual(frappe.session.user, "Guest")

	def test_uv_setup_step_up_flips_then_passwordless_works(self):
		user = self._user()
		# a conditional-create-style credential is born uv_initialized=0
		auth, _ = self._enroll(user, uv=False)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "uv_initialized"), 0)

		# a UV=1 assertion against it yields UVSetupRequired + a setup_id
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True, sign_count=3)
		with self.assertRaises(UVSetupRequired):
			self._verify(begun["state_id"], credential, binder)
		setup_id = frappe.local.response.get("setup_id")
		self.assertTrue(setup_id)

		# the one-time password step-up flips uv_initialized and mints a session
		self._request("/api/method/passkeys.passkey.complete_uv_setup", binder=binder)
		passkey.complete_uv_setup(setup_id, PWD)
		self.assertEqual(frappe.session.user, user)
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "uv_initialized"), 1)

		# subsequent logins are purely passwordless
		frappe.set_user("Guest")
		begun2, binder2 = self._begin()
		credential2 = self._assert(auth, begun2["options"], uv=True, sign_count=4)
		self._verify(begun2["state_id"], credential2, binder2)
		self.assertEqual(frappe.session.user, user)

	def test_complete_uv_setup_wrong_password_rejected(self):
		user = self._user()
		auth, _ = self._enroll(user, uv=False)
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True)
		with self.assertRaises(UVSetupRequired):
			self._verify(begun["state_id"], credential, binder)
		setup_id = frappe.local.response.get("setup_id")
		self._request("/api/method/passkeys.passkey.complete_uv_setup", binder=binder)
		with self.assertRaises(frappe.AuthenticationError):
			passkey.complete_uv_setup(setup_id, "wrong-password")

	# ======================================================================
	# single-use + rate limit
	# ======================================================================

	def test_state_is_single_use(self):
		user = self._user()
		auth, _ = self._enroll(user)
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"])
		self._verify(begun["state_id"], credential, binder)
		frappe.set_user("Guest")
		# a replay of the consumed state fails closed
		with self.assertRaises(CeremonyExpired):
			self._verify(begun["state_id"], credential, binder)

	def test_begin_login_rate_limited(self):
		# begin_login is 30/min/IP; the 31st on one IP is refused
		with self.assertRaises(frappe.RateLimitExceededError):
			for _ in range(31):
				self._begin()

	# ======================================================================
	# guest translations endpoint (§5.6)
	# ======================================================================

	def test_translations_endpoint_serves_app_strings_for_guest(self):
		frappe.set_user("Guest")
		self._request("/api/method/passkeys.passkey.get_app_translations")
		frappe.local.lang = "fr"
		catalog = passkey.get_app_translations(version="1")
		self.assertIsInstance(catalog, dict)
		self.assertEqual(catalog.get("Sign in with a passkey"), "Se connecter avec une clé d'accès")

	# ======================================================================
	# §12.5 security regression rows on the first-factor surface
	# ======================================================================

	def test_splice_register_state_cannot_verify_a_login(self):
		"""A register-type ceremony fed to verify_login is rejected before any
		assertion is looked at (type-scoped records, §3.1 step 3 / §12.5 splice)."""
		state_id = state.store_ceremony(
			{
				"v": 1,
				"type": "register",
				"user": "x",
				"challenge_b64": "YQ",
				"rp_id": RP_ID,
				"origins": [ORIGIN],
			}
		)
		self._request("/api/method/passkeys.passkey.verify_login")
		with self.assertRaises(CeremonyExpired):
			passkey.verify_login(state_id, {"id": "z", "response": {"userHandle": "h"}})

	def test_first_factor_cross_user_substitution_is_uniform_failure(self):
		"""StrongKey class (§12.5): user B's valid assertion carrying user A's
		userHandle must fail uniformly — a credential must belong to the account its
		handle resolves to (both halves)."""
		user_a = self._user()
		self._enroll(user_a, seed="xuserA")
		handle_a = frappe.db.get_value("WebAuthn User Handle", {"user": user_a}, "handle")
		user_b = self._user()
		auth_b, _ = self._enroll(user_b, seed="xuserB")

		begun, binder = self._begin()
		credential = self._assert(auth_b, begun["options"])  # B's own valid assertion
		credential["response"]["userHandle"] = handle_a  # ...but claiming to be A
		self._request("/api/method/passkeys.passkey.verify_login", binder=binder)
		with self.assertRaises(frappe.AuthenticationError):
			passkey.verify_login(begun["state_id"], credential)

	def test_begin_login_refuses_a_foreign_request_origin(self):
		"""Cross-site origin (§12.5): a request whose Origin is not in the configured
		origins fails closed at begin (host-mismatch diagnosability, §9.2)."""
		set_request(
			method="POST",
			path="/api/method/passkeys.passkey.begin_login",
			headers=[("Origin", "https://evil.example.net")],
		)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = frappe.generate_hash(length=12)
		frappe.local.form_dict = frappe._dict()
		with self.assertRaises(frappe.AuthenticationError):
			passkey.begin_login()

	def test_host_mismatch_writes_structured_log(self):
		"""S10 / §9.2 / B-F10: a host-mismatch refusal on the begin_login path writes
		ONE structured log line (previously only the registration path logged; the
		begin_login / begin_confirmation / verify legs were silent)."""
		# reset the request after us so the foreign Origin never leaks into a later
		# test's _enroll (which begins a registration without re-setting the request).
		self.addCleanup(set_request, method="POST", path="/api/method/passkeys.passkey.begin_login")
		set_request(
			method="POST",
			path="/api/method/passkeys.passkey.begin_login",
			headers=[("Origin", "https://evil.example.net")],
		)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = frappe.generate_hash(length=12)
		frappe.local.form_dict = frappe._dict()
		with patch.object(frappe, "log_error") as mock_log:
			with self.assertRaises(frappe.AuthenticationError):
				passkey.begin_login()
		self.assertTrue(mock_log.called)
		titles = " ".join(str(c.kwargs.get("title", "")) for c in mock_log.call_args_list)
		self.assertIn("request host not in configured origins", titles)

	# ======================================================================
	# uv-setup completion hardening: enabled recheck, flag carry, upward-only
	# ======================================================================

	def test_complete_uv_setup_refuses_disabled_user(self):
		"""C4: the uv-setup record outlives the assertion by up to 180 s; a user
		disabled in that window is refused at complete_uv_setup — no session, and the
		uv_initialized flip never happens (mirrors verify_login step 10)."""
		user = self._user()
		auth, _ = self._enroll(user, uv=False)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True)
		with self.assertRaises(UVSetupRequired):
			self._verify(begun["state_id"], credential, binder)
		setup_id = frappe.local.response.get("setup_id")

		frappe.db.set_value("User", user, "enabled", 0)  # admin disable mid-window
		self._request("/api/method/passkeys.passkey.complete_uv_setup", binder=binder)
		with self.assertRaises(frappe.AuthenticationError):
			passkey.complete_uv_setup(setup_id, PWD)
		self.assertEqual(frappe.session.user, "Guest")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "uv_initialized"), 0)
		frappe.db.set_value("User", user, "enabled", 1)  # let the committing sweep delete it

	def test_uv_setup_leg_regressed_count_flags_credential(self):
		"""SEC-2: the uv-setup login leg is the SOLE advance for its assertion — a
		sign-count regression on that first UV=1 login must still flag the credential
		AND fire the owner notification after complete_uv_setup (default soft policy)."""
		user = self._user()
		auth, _ = self._enroll(user, uv=False)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		# raise the stored counter so the assertion (sign_count=5) regresses
		frappe.db.set_value("WebAuthn Credential", name, "sign_count", 100, update_modified=False)

		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True, sign_count=5)
		with self.assertRaises(UVSetupRequired):
			self._verify(begun["state_id"], credential, binder)
		setup_id = frappe.local.response.get("setup_id")

		with patch("passkeys.notifications.notify_credential_flagged") as mock_notify:
			self._request("/api/method/passkeys.passkey.complete_uv_setup", binder=binder)
			passkey.complete_uv_setup(setup_id, PWD)

		self.assertEqual(frappe.session.user, user)
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "flagged"), 1)
		self.assertEqual(
			frappe.db.get_value("WebAuthn Credential", name, "flagged_reason"), "sign_count_regression"
		)
		self.assertTrue(mock_notify.called)

	def test_complete_uv_setup_does_not_lower_concurrent_counter(self):
		"""SEC-3: complete_uv_setup writes the STASHED sign_count; a concurrent advance
		that raised the stored counter past the stash must NOT be regressed by the
		late write — the write is upward-only (policy.sign_count_to_store)."""
		user = self._user()
		auth, _ = self._enroll(user, uv=False)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")

		begun, binder = self._begin()
		credential = self._assert(auth, begun["options"], uv=True, sign_count=5)  # stash N1=5
		with self.assertRaises(UVSetupRequired):
			self._verify(begun["state_id"], credential, binder)
		setup_id = frappe.local.response.get("setup_id")

		# a concurrent 2FA/confirm advance raises the stored counter to N2 > N1
		frappe.db.set_value("WebAuthn Credential", name, "sign_count", 50, update_modified=False)

		self._request("/api/method/passkeys.passkey.complete_uv_setup", binder=binder)
		passkey.complete_uv_setup(setup_id, PWD)

		self.assertEqual(frappe.session.user, user)
		# never regressed to the stashed 5 — the concurrent N2=50 is preserved
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "sign_count"), 50)

	def test_failed_verify_login_feeds_login_attempt_tracker(self):
		"""S6: N failed passkey verifies feed core's LoginAttemptTracker for the
		resolved user (§3/§6.3), exactly as a bad password would — without leaking
		user existence (the wire is still a uniform 401, no lock raised here)."""
		from frappe.auth import get_login_attempt_tracker

		user = self._user()
		auth, _ = self._enroll(user)
		del get_login_attempt_tracker(user, raise_locked_exception=False).login_failed_count

		for _n in range(3):
			begun, binder = self._begin()
			# correct id + userHandle (resolves the user) but signed over the WRONG
			# challenge → the crypto verify fails PAST resolution
			bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
			with self.assertRaises(frappe.AuthenticationError):
				self._verify(begun["state_id"], bad, binder)

		fresh = get_login_attempt_tracker(user, raise_locked_exception=False)
		self.assertEqual(int(fresh.login_failed_count or 0), 3)
		self.assertEqual(frappe.session.user, "Guest")  # no session leaked


def _b64url_decode(value: str) -> bytes:
	import base64

	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
