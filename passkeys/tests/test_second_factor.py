# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Second-factor (password → passkey step-up) battery on the live bench
(DESIGN-v1 §6, §6.1, §6.3, §6.4, §12.2). Drives the two-leg flow end to end with
the soft authenticator: leg 1 verifies the password via core's own
``authenticate`` and returns core's ``verification``/``tmp_id`` envelope; leg 2
verifies the passkey assertion, re-runs core-equivalent re-authentication (F14),
and mints via the one ``login_as`` choke point.

Covered: full 2-leg success; wrong password ⇒ no challenge; wrong/absent
assertion ⇒ typed re-arm with an attempt cap of 3 then terminal; binder
set-if-absent on leg 1 (no prior ``begin_login``, F12); mid-ceremony password
change AND user-disable both fail closed (F14); OTP fallback knob ON completes
via core OTP, knob OFF refuses server-side; the two-way 2FA floor guard; and
compose-with-core-OTP (dispatch, never stack)."""

import frappe
from frappe.auth import CookieManager, LoginManager
from frappe.utils import set_request
from frappe.utils.password import update_password

from passkeys import passkey, state
from passkeys.api import registration
from passkeys.passkey import CeremonyExpired
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator

RP_ID = "example.com"
ORIGIN = "https://example.com"
PWD = "Secret_passw0rd_9x!"


class SecondFactorTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._settings_snap = frappe.db.get_singles_dict("Passkey Settings")
		self._ss_2fa = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		self._ss_method = frappe.db.get_single_value("System Settings", "two_factor_method")
		self._ss_disable = frappe.db.get_single_value("System Settings", "disable_user_pass_login")

		self._set_system_2fa(enabled=1, method="OTP App", disable_pass=0)
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 0
		settings.passkey_as_second_factor = 1
		settings.passkey_2fa_allow_otp_fallback = 0
		settings.passkey_sign_count_hard_fail = 0
		settings.save(ignore_permissions=True)
		self._sync_settings()

		# a role that carries core 2FA, so should_run_2fa(user) is True for the
		# users we opt in (drives pwd retention + OTP fallback availability).
		self._role = self._ensure_2fa_role()

		self._ip = frappe.generate_hash(length=12)
		self.addCleanup(self._restore)

	def tearDown(self):
		# leg 2 mints a session via login_as, which COMMITS mid-test — sweep the
		# committed rows AFTER the runner's rollback (mirrors test_login_api).
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	# -- settings plumbing --------------------------------------------------

	def _set_system_2fa(self, *, enabled, method=None, disable_pass=0):
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", enabled)
		if method is not None:
			frappe.db.set_single_value("System Settings", "two_factor_method", method)
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", disable_pass)
		frappe.local.system_settings = None  # bust the request-local cache
		frappe.clear_document_cache("System Settings", "System Settings")

	def _sync_settings(self):
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _set_passkey_setting(self, field, value):
		frappe.db.set_single_value("Passkey Settings", field, value)
		self._sync_settings()

	def _ensure_2fa_role(self) -> str:
		name = "Passkey 2FA Test Role"
		if not frappe.db.exists("Role", name):
			frappe.get_doc(
				{"doctype": "Role", "role_name": name, "two_factor_auth": 1, "desk_access": 0}
			).insert(ignore_permissions=True)
		elif not frappe.db.get_value("Role", name, "two_factor_auth"):
			frappe.db.set_value("Role", name, "two_factor_auth", 1)
		return name

	def _restore(self):
		frappe.set_user("Administrator")
		self._set_system_2fa(
			enabled=self._ss_2fa or 0,
			method=self._ss_method or "OTP App",
			disable_pass=self._ss_disable or 0,
		)
		for field in (
			"login_with_passkey",
			"passkey_as_second_factor",
			"passkey_2fa_allow_otp_fallback",
			"passkey_rp_id",
			"passkey_origins",
			"passkey_sign_count_hard_fail",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._settings_snap.get(field) or 0)
		self._sync_settings()

	# -- fixtures -----------------------------------------------------------

	def _user(self, *, otp_capable=False) -> str:
		user = make_user()
		update_password(user, PWD)
		if otp_capable:
			frappe.get_doc("User", user).add_roles(self._role)
			# force the OTP-App verification path away from the email branch
			# (twofactor stores this Default under parent="__2fa")
			from frappe.twofactor import set_default

			set_default(user + "_otplogin", 1)
		return user

	def _enroll(self, user, seed="sf") -> SoftAuthenticator:
		frappe.set_user(user)
		state.set_sudo_window(frappe.session.sid, {"user": user, "seeded_by": "password"}, ttl=600)
		begun = registration.begin_registration(flow="explicit")
		auth = SoftAuthenticator(seed=f"{seed}-{self._ip}")
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"],
			rp_id=RP_ID,
			origin=ORIGIN,
			uv=True,
			credprops_rk=True,
		)
		registration.verify_registration(begun["state_id"], credential)
		handle = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
		auth.user_handle = _b64url_decode(handle)
		frappe.set_user("Guest")
		return auth

	# -- request harness ----------------------------------------------------

	def _request(self, path, *, binder=None, usr=None, pwd=None):
		headers = [("Cookie", f"{state.BINDER_COOKIE}={binder}")] if binder else None
		set_request(method="POST", path=path, headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = self._ip
		frappe.local.form_dict = frappe._dict()
		frappe.local.response = frappe._dict()
		frappe.local.login_manager = None  # endpoint builds a fresh one per leg
		if usr is not None:
			frappe.local.form_dict["usr"] = usr
			frappe.local.form_dict["pwd"] = pwd

	def _leg1(self, usr, pwd, binder=None):
		self._request("/api/method/passkeys.passkey.login_with_password", binder=binder, usr=usr, pwd=pwd)
		passkey.login_with_password(usr, pwd)
		resp = frappe.local.response
		set_binder = frappe.local.cookie_manager.cookies.get(state.BINDER_COOKIE)
		return resp, (set_binder["value"] if set_binder else None)

	def _leg2(self, state_id, credential, binder):
		self._request("/api/method/passkeys.passkey.verify_second_factor", binder=binder)
		return passkey.verify_second_factor(state_id, credential)

	def _assert(self, auth, options, **kw):
		return auth.assertion(challenge_b64=options["challenge"], rp_id=RP_ID, origin=ORIGIN, **kw)

	# ======================================================================
	# full 2-leg success
	# ======================================================================

	def test_password_plus_passkey_two_leg_success_mints_session(self):
		user = self._user()
		auth = self._enroll(user)

		resp, binder = self._leg1(user, PWD)
		self.assertTrue(binder)  # F12: leg 1 minted the binder with no prior begin_login
		self.assertEqual(resp["verification"]["method"], "Passkey")
		self.assertIn("options", resp["verification"])
		self.assertTrue(resp["tmp_id"])

		credential = self._assert(auth, resp["verification"]["options"], sign_count=7)
		self._leg2(resp["tmp_id"], credential, binder)

		self.assertEqual(frappe.session.user, user)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "sign_count"), 7)

	def test_mode_off_refuses_before_authentication(self):
		user = self._user()
		self._enroll(user)  # enroll while a mode is still on
		self._set_passkey_setting("passkey_as_second_factor", 0)
		with self.assertRaises(frappe.AuthenticationError):
			self._leg1(user, PWD)

	# ======================================================================
	# wrong password ⇒ no challenge
	# ======================================================================

	def test_wrong_password_no_challenge(self):
		user = self._user()
		self._enroll(user)
		with self.assertRaises(frappe.AuthenticationError):
			self._leg1(user, "wrong-password")
		# no passkey challenge was ever minted
		self.assertNotIn("verification", frappe.local.response)
		self.assertEqual(frappe.session.user, "Guest")

	# ======================================================================
	# failed passkey ⇒ typed re-arm, attempt cap 3, then terminal (§6.3/A37)
	# ======================================================================

	def test_failed_passkey_rearms_then_caps_at_three(self):
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		sid = resp["tmp_id"]

		# a valid-membership assertion signed over the WRONG challenge fails the
		# crypto check → the state is re-armed with a fresh challenge (attempt 1,2).
		for _attempt in range(2):
			bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
			with self.assertRaises(CeremonyExpired):
				self._leg2(sid, bad, binder)
			fresh = frappe.local.response.get("state_id")
			self.assertTrue(fresh, "expected a re-armed state_id in the 401 body")
			self.assertIn("options", frappe.local.response.get("verification", {}))
			sid = fresh

		# third failure hits the cap → terminal: CeremonyExpired with NO re-arm
		bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
		with self.assertRaises(CeremonyExpired):
			self._leg2(sid, bad, binder)
		self.assertIsNone(frappe.local.response.get("state_id"))
		self.assertEqual(frappe.session.user, "Guest")

	def test_failed_passkey_then_retry_succeeds_on_rearmed_state(self):
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)

		bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
		with self.assertRaises(CeremonyExpired):
			self._leg2(resp["tmp_id"], bad, binder)
		fresh_sid = frappe.local.response["state_id"]
		fresh_options = frappe.local.response["verification"]["options"]

		# retry the re-armed state with a good assertion → success
		good = self._assert(auth, fresh_options, sign_count=4)
		self._leg2(fresh_sid, good, binder)
		self.assertEqual(frappe.session.user, user)

	def test_absent_binder_on_leg2_fails_closed(self):
		user = self._user()
		auth = self._enroll(user)
		resp, _binder = self._leg1(user, PWD)
		credential = self._assert(auth, resp["verification"]["options"])
		with self.assertRaises(frappe.AuthenticationError):
			self._leg2(resp["tmp_id"], credential, binder=None)
		self.assertEqual(frappe.session.user, "Guest")

	def test_cross_ceremony_membership_miss_is_refused(self):
		# an assertion from a credential that is NOT in this ceremony's allow-list
		user = self._user()
		self._enroll(user, seed="owned")
		stranger = SoftAuthenticator(seed=f"stranger-{self._ip}")
		stranger.user_handle = b"\x02" * 16
		resp, binder = self._leg1(user, PWD)
		bogus = self._assert(stranger, resp["verification"]["options"])
		with self.assertRaises(CeremonyExpired):  # re-arm path (membership miss)
			self._leg2(resp["tmp_id"], bogus, binder)
		self.assertEqual(frappe.session.user, "Guest")

	# ======================================================================
	# F14 — mid-ceremony revocation must NOT mint a session
	# ======================================================================

	def test_password_change_between_legs_blocks_session(self):
		# pwd is cached only under the fallback conjunction (2FA-capable + knob on)
		self._set_passkey_setting("passkey_2fa_allow_otp_fallback", 1)
		user = self._user(otp_capable=True)
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		credential = self._assert(auth, resp["verification"]["options"], sign_count=6)

		# the canonical compromise response: password rotated mid-ceremony
		update_password(user, "A_Different_passw0rd_2y!")

		with self.assertRaises(frappe.AuthenticationError):
			self._leg2(resp["tmp_id"], credential, binder)
		self.assertEqual(frappe.session.user, "Guest")

	def test_user_disabled_between_legs_blocks_session(self):
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		credential = self._assert(auth, resp["verification"]["options"], sign_count=6)

		frappe.db.set_value("User", user, "enabled", 0)  # admin disable mid-flow

		with self.assertRaises(frappe.AuthenticationError):
			self._leg2(resp["tmp_id"], credential, binder)
		self.assertEqual(frappe.session.user, "Guest")
		frappe.db.set_value("User", user, "enabled", 1)  # let the sweep delete it

	# ======================================================================
	# OTP fallback knob — both directions (§6.3)
	# ======================================================================

	def test_otp_fallback_on_completes_via_core_otp(self):
		self._set_passkey_setting("passkey_2fa_allow_otp_fallback", 1)
		user = self._user(otp_capable=True)
		self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		# leg 1 offered the fallback (user OTP-capable ∧ knob on)
		self.assertTrue(resp["verification"]["fallback"]["otp"])

		# the user gives up on the passkey and takes the code instead
		self._request("/api/method/passkeys.passkey.fallback_to_otp", binder=binder)
		passkey.fallback_to_otp(resp["tmp_id"])
		# core's OTP envelope rode back (a non-passkey verification + tmp_id)
		self.assertTrue(frappe.local.response.get("tmp_id"))
		self.assertNotEqual(frappe.local.response.get("verification", {}).get("method"), "Passkey")

	def test_otp_fallback_off_is_refused_server_side(self):
		# knob OFF: no downgrade offered in the envelope AND a direct call refused
		self._set_passkey_setting("passkey_2fa_allow_otp_fallback", 0)
		user = self._user(otp_capable=True)
		self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		self.assertFalse(resp["verification"]["fallback"]["otp"])

		self._request("/api/method/passkeys.passkey.fallback_to_otp", binder=binder)
		with self.assertRaises(frappe.AuthenticationError):
			passkey.fallback_to_otp(resp["tmp_id"])

	def test_failed_passkey_then_otp_fallback_still_completes(self):
		# a failed leg-2 re-arm must not destroy the OTP-fallback capability
		self._set_passkey_setting("passkey_2fa_allow_otp_fallback", 1)
		user = self._user(otp_capable=True)
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)

		bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
		with self.assertRaises(CeremonyExpired):
			self._leg2(resp["tmp_id"], bad, binder)
		fresh_sid = frappe.local.response["state_id"]

		self._request("/api/method/passkeys.passkey.fallback_to_otp", binder=binder)
		passkey.fallback_to_otp(fresh_sid)
		self.assertTrue(frappe.local.response.get("tmp_id"))

	# ======================================================================
	# compose with core OTP (§6.4) — dispatch, never stack
	# ======================================================================

	def test_compose_passkey_holder_gets_passkey_passwordless_of_otp(self):
		user = self._user(otp_capable=True)  # core 2FA covers this user
		self._enroll(user)
		resp, _binder = self._leg1(user, PWD)
		# a passkey holder is dispatched to the passkey, NOT stacked onto OTP
		self.assertEqual(resp["verification"]["method"], "Passkey")

	def test_compose_passkeyless_user_gets_core_otp(self):
		user = self._user(otp_capable=True)  # 2FA-covered but NO credential enrolled
		resp, _binder = self._leg1(user, PWD)
		# no passkey ⇒ core's OTP dispatch fires (verification set, not Passkey)
		self.assertTrue(resp.get("tmp_id"))
		self.assertNotEqual(resp.get("verification", {}).get("method"), "Passkey")

	# ======================================================================
	# 2FA floor — BOTH directions (§6.1)
	# ======================================================================

	def test_floor_forward_settings_refuse_enabling_without_core_2fa(self):
		# forward half: Passkey Settings validator refuses passkey_as_second_factor
		# while core enable_two_factor_auth is off
		self._set_system_2fa(enabled=0, method="OTP App")
		doc = frappe.get_doc("Passkey Settings")
		doc.passkey_as_second_factor = 1
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)

	def test_floor_reverse_system_settings_guard_blocks_1_to_0_flip(self):
		# reverse half: the doc_events guard refuses flipping enable_two_factor_auth
		# 1→0 while passkey_as_second_factor is on (already 1 from setUp)
		ss = frappe.get_doc("System Settings")
		ss.enable_two_factor_auth = 0
		with self.assertRaises(frappe.ValidationError):
			ss.save(ignore_permissions=True)
		# the floor still holds
		self.assertEqual(frappe.db.get_single_value("System Settings", "enable_two_factor_auth"), 1)

	# ======================================================================
	# C5 — a malformed credential id is a uniform 401 + re-arm (not a 500)
	# ======================================================================

	def test_garbage_credential_id_rearms_not_500(self):
		"""C5: a malformed base64url credential id past the single-use state consume
		must raise the uniform 401 (never a raw binascii/500) AND route through the
		re-arm path — so the 2FA leg is NOT burned. A retry with a valid assertion on
		the re-armed state then completes."""
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)

		# "AAAAA" = 5 base64url data chars (≡ 1 mod 4) — undecodable. Before the fix it
		# raised binascii.Error → 500 with the state already consumed (dead 2FA leg).
		garbage = {"id": "AAAAA", "rawId": "AAAAA", "response": {}, "type": "public-key"}
		with self.assertRaises(CeremonyExpired):
			self._leg2(resp["tmp_id"], garbage, binder)
		fresh_sid = frappe.local.response.get("state_id")
		self.assertTrue(fresh_sid, "state must be re-armed, not burned, on a garbage id")
		fresh_options = frappe.local.response["verification"]["options"]

		good = self._assert(auth, fresh_options, sign_count=8)
		self._leg2(fresh_sid, good, binder)
		self.assertEqual(frappe.session.user, user)

	# ======================================================================
	# S3 — the app's plain-password arm seeds a "password" sudo window
	# ======================================================================

	def test_app_plain_password_arm_seeds_password_window(self):
		"""S3: the app's own plain-password arm (a passkey-less, 2FA-less user's
		LDAP-style finish in ``login_with_password``) mints a session whose sudo
		window is classified "password", not "weak". Its endpoint path is not
		/api/method/login, so ``_classify_login_method`` would otherwise mis-seed
		"weak" and re-fire the §8.4 conditional-create nudge seconds after login."""
		user = self._user()  # no passkey enrolled, no 2FA role → plain finish
		self._leg1(user, PWD)
		self.assertEqual(frappe.session.user, user)
		window = state.get_sudo_window(frappe.session.sid)
		self.assertEqual((window or {}).get("seeded_by"), "password")

	# ======================================================================
	# S6 — a failed leg-2 passkey feeds core's LoginAttemptTracker
	# ======================================================================

	def test_failed_second_factor_feeds_login_attempt_tracker(self):
		"""S6: a wrong leg-2 passkey feeds core's LoginAttemptTracker for the resolved
		(leg-1) user, exactly as a bad password would (§6.3) — without leaking user
		existence (the wire stays the re-arm 401)."""
		from frappe.auth import get_login_attempt_tracker

		user = self._user()
		auth = self._enroll(user)
		del get_login_attempt_tracker(user, raise_locked_exception=False).login_failed_count

		resp, binder = self._leg1(user, PWD)
		sid = resp["tmp_id"]
		for _n in range(2):
			bad = auth.assertion(challenge_b64=frappe.generate_hash(), rp_id=RP_ID, origin=ORIGIN)
			with self.assertRaises(CeremonyExpired):
				self._leg2(sid, bad, binder)
			sid = frappe.local.response.get("state_id")
			self.assertTrue(sid)

		fresh = get_login_attempt_tracker(user, raise_locked_exception=False)
		self.assertEqual(int(fresh.login_failed_count or 0), 2)


def _b64url_decode(value: str) -> bytes:
	import base64

	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
