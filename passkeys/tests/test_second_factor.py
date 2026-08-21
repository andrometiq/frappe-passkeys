# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Second-factor (password → passkey step-up) battery on the live bench.
Drives the two-leg flow end to end with
the soft authenticator: leg 1 verifies the password via core's own
``authenticate`` and returns core's ``verification``/``tmp_id`` envelope; leg 2
verifies the passkey assertion, re-runs core-equivalent re-authentication,
and mints via the one ``login_as`` choke point.

Covered: full 2-leg success; wrong password ⇒ no challenge; wrong/absent
assertion ⇒ typed re-arm with an attempt cap of 3 then terminal; binder
set-if-absent on leg 1 (no prior ``begin_login``); mid-ceremony password
change AND user-disable both fail closed; OTP fallback knob ON completes
via core OTP, knob OFF refuses server-side; the two-way 2FA floor guard; and
compose-with-core-OTP (dispatch, never stack)."""

from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import frappe
from frappe.auth import CookieManager
from frappe.utils import set_request
from frappe.utils.password import update_password

from passkeys import auth_hooks, passkey, state
from passkeys.api import registration
from passkeys.passkey import CeremonyExpired
from passkeys.tests.compat import IntegrationTestCase, WebAuthnAssertMixin, flush_settings_cache
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator, b64url, b64url_decode

RP_ID = "example.com"
ORIGIN = "https://example.com"
PWD = "Secret_passw0rd_9x!"


class _LoginTarget:
	def __init__(self, user):
		self.user = user


class SecondFactorTest(WebAuthnAssertMixin, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		frappe.local.flags.pop("passkey_login", None)
		self._settings_snap = frappe.db.get_singles_dict("Passkey Settings")
		self._ss_2fa = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		self._ss_method = frappe.db.get_single_value("System Settings", "two_factor_method")
		self._ss_disable = frappe.db.get_single_value("System Settings", "disable_user_pass_login")

		self._set_system_2fa(enabled=1, method="OTP App", disable_pass=0)
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ORIGIN
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
		flush_settings_cache()

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
			# Text singles must not be restored as the truthy string "0".
			default = "" if field in {"passkey_rp_id", "passkey_origins"} else 0
			frappe.db.set_single_value("Passkey Settings", field, self._settings_snap.get(field) or default)
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
		auth.user_handle = b64url_decode(handle)
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

	# ======================================================================
	# full 2-leg success
	# ======================================================================

	def test_password_plus_passkey_two_leg_success_mints_session(self):
		user = self._user()
		auth = self._enroll(user)

		resp, binder = self._leg1(user, PWD)
		self.assertTrue(binder)  # leg 1 minted the binder with no prior begin_login
		self.assertEqual(resp["verification"]["method"], "Passkey")
		self.assertIn("options", resp["verification"])
		self.assertTrue(resp["tmp_id"])

		credential = self._assert(auth, resp["verification"]["options"], sign_count=7)
		self._leg2(resp["tmp_id"], credential, binder)

		self.assertEqual(frappe.session.user, user)
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "sign_count"), 7)

	def test_passkey_only_user_two_factor_mints_via_flag_and_seeds_passkey_window(self):
		"""A ``passkey_only_login=1`` user completes password+passkey 2FA.
		Leg 2 (verify_second_factor) sets ``frappe.local.flags.passkey_login`` before
		``login_as`` (passkey.py ~:549), so the REAL ``on_login`` veto EXEMPTS the mint
		via that flag — a flagged user is not locked out of their own 2FA — and
		``seed_sudo_window`` classifies the window "passkey", not "weak". The
		second-factor analog of test_login_api's passkey_only passwordless round-trip."""
		user = self._user()
		auth = self._enroll(user)
		frappe.db.set_value(
			"WebAuthn User Handle", {"user": user}, "passkey_only_login", 1, update_modified=False
		)
		frappe.local.flags.pop("passkey_login", None)  # a leaked flag would false-pass

		resp, binder = self._leg1(user, PWD)
		credential = self._assert(auth, resp["verification"]["options"], sign_count=7)
		frappe.local.flags.pop("passkey_login", None)  # prove leg 2 sets the flag itself
		self._leg2(resp["tmp_id"], credential, binder)

		# the veto let the flagged user's 2FA mint through (its own passkey_login flag)
		self.assertEqual(frappe.session.user, user)
		window = state.get_sudo_window(frappe.session.sid)
		self.assertEqual((window or {}).get("seeded_by"), "passkey")

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
	# failed passkey ⇒ typed re-arm, attempt cap 3, then terminal
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
	# mid-ceremony revocation must NOT mint a session
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

	def test_password_change_blocks_when_otp_fallback_is_off(self):
		"""The password-version marker is unconditional; plaintext retention is not."""
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		record = state.consume_ceremony(resp["tmp_id"])
		self.assertIsNone(record.get("pwd"))
		self.assertTrue(record.get("password_version"))
		# Put back an equivalent one-shot state so the real leg-two path consumes it.
		state_id = state.store_ceremony(record)
		credential = self._assert(auth, resp["verification"]["options"], sign_count=6)
		update_password(user, "A_Different_passw0rd_2y!")

		with self.assertRaises(frappe.AuthenticationError):
			self._leg2(state_id, credential, binder)
		self.assertEqual(frappe.session.user, "Guest")

	def test_external_auth_without_local_hash_retains_password_for_leg2_reauth(self):
		user = self._user()
		self._enroll(user)
		with patch.object(passkey, "_password_version", return_value=None):
			resp, _binder = self._leg1(user, PWD)
		record = state.consume_ceremony(resp["tmp_id"])
		self.assertEqual(record.get("pwd"), PWD)
		self.assertIsNone(record.get("password_version"))

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
	# final on_login enforcement: stock/core/alternate paths cannot bypass
	# ======================================================================

	def _run_login_veto(self, user, *, path="/api/method/login", **form_values):
		frappe.set_user("Guest")
		frappe.local.flags.pop("passkey_login", None)
		self._request(path)
		frappe.form_dict.update(form_values)
		return auth_hooks.on_login_veto(login_manager=_LoginTarget(user))

	def test_uncovered_user_stock_login_is_vetoed(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(user)

	def test_alternate_login_is_also_vetoed_for_enrolled_user(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		# No request-path heuristic: email-link/social/LDAP post_login reaches the
		# same final hook and cannot silently bypass the selected second factor.
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(user, path="/api/method/frappe.www.login.login_via_key")

	def test_verified_passkey_leg_passes_final_veto(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		frappe.set_user("Guest")
		frappe.local.flags.passkey_login = True
		self.assertIsNone(auth_hooks.on_login_veto(login_manager=_LoginTarget(user)))

	def test_one_time_otp_fallback_marker_passes_then_replay_fails(self):
		user = self._user(otp_capable=True)
		self._enroll(user)
		tmp_id = frappe.generate_hash()
		state.store_otp_fallback(tmp_id, {"v": 1, "user": user})
		self.assertIsNone(self._run_login_veto(user, tmp_id=tmp_id, otp="123456"))
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(user, tmp_id=tmp_id, otp="123456")

	def test_otp_marker_cannot_be_consumed_by_an_alternate_login_route(self):
		user = self._user(otp_capable=True)
		self._enroll(user)
		tmp_id = frappe.generate_hash()
		state.store_otp_fallback(tmp_id, {"v": 1, "user": user})
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(
				user,
				path="/api/method/frappe.www.login.login_via_key",
				tmp_id=tmp_id,
				otp="attacker-controlled",
			)
		# The rejected route did not burn the marker; a core OTP completion can use it.
		self.assertIsNone(self._run_login_veto(user, tmp_id=tmp_id, otp="123456"))

	def test_otp_fallback_marker_is_user_bound(self):
		user = self._user(otp_capable=True)
		other = self._user(otp_capable=True)
		self._enroll(user)
		self._enroll(other, seed="sf-other")
		tmp_id = frappe.generate_hash()
		state.store_otp_fallback(tmp_id, {"v": 1, "user": other})
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(user, tmp_id=tmp_id, otp="123456")
		self.assertEqual(state.get_otp_fallback(tmp_id).get("user"), other)
		self.assertIsNone(self._run_login_veto(other, tmp_id=tmp_id, otp="123456"))

	def test_otp_marker_is_not_consumed_after_core_2fa_policy_is_removed(self):
		user = self._user(otp_capable=True)
		self._enroll(user)
		tmp_id = frappe.generate_hash()
		state.store_otp_fallback(tmp_id, {"v": 1, "user": user})
		with patch("frappe.twofactor.should_run_2fa", return_value=False):
			with self.assertRaises(frappe.AuthenticationError):
				self._run_login_veto(user, tmp_id=tmp_id, otp="123456")
		# A policy race cannot burn the marker; a genuinely covered core OTP leg can.
		with patch("frappe.twofactor.should_run_2fa", return_value=True):
			self.assertIsNone(self._run_login_veto(user, tmp_id=tmp_id, otp="123456"))

	def test_reset_key_v2_trailing_slash_changes_password_but_mints_only_guest(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		from frappe.auth import LoginManager
		from frappe.core.doctype.user.user import update_password as complete_password_reset
		from frappe.utils.password import check_password

		link = frappe.get_doc("User", user)._reset_password(send_email=False)
		key = parse_qs(urlparse(link).query)["key"][0]
		method = "frappe.core.doctype.user.user.update_password"
		self._request(f"/api/v2/method/{method}/")
		frappe.local.form_dict.update({"cmd": method, "key": key})
		frappe.local.login_manager = LoginManager()
		# LoginManager may resume the test harness's prior cookie; the public reset
		# endpoint is a Guest request, so pin the real attack/recovery boundary.
		frappe.set_user("Guest")
		new_password = "Reset_passw0rd_4z!"

		complete_password_reset(new_password, key=key)

		self.assertEqual(frappe.local.login_manager.user, "Guest")
		self.assertEqual(frappe.session.user, "Guest")
		self.assertEqual(check_password(user, new_password), user)

	def test_arbitrary_login_cannot_claim_password_reset_exemption(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		with self.assertRaises(frappe.AuthenticationError):
			self._run_login_veto(user, key="valid-reset-key")

	def test_missing_encryption_key_never_stores_plaintext_password(self):
		user = self._user(otp_capable=False)
		self._enroll(user)
		original = frappe.local.conf.get("encryption_key")
		self.addCleanup(frappe.local.conf.__setitem__, "encryption_key", original)
		frappe.local.conf["encryption_key"] = None
		with patch("passkeys.state.store_ceremony") as store:
			with self.assertRaisesRegex(frappe.AuthenticationError, "encryption key"):
				self._leg1(user, PWD)
		store.assert_not_called()

	# ======================================================================
	# OTP fallback knob — both directions
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

	def test_otp_fallback_records_risk_event_in_activity_log(self):
		"""FIDO-downgrade telemetry: when ``fallback_to_otp`` actually runs
		(a passkey holder chooses phishable OTP), ``_record_fallback_used`` fires and
		writes a ``RISK_FALLBACK_USED`` row to the Activity Log. The envelope test above
		asserts only the core-OTP hand-off; this pins that the risk-event row is real."""
		from passkeys import notifications

		self._set_passkey_setting("passkey_2fa_allow_otp_fallback", 1)
		user = self._user(otp_capable=True)
		self._enroll(user)
		resp, binder = self._leg1(user, PWD)

		self._request("/api/method/passkeys.passkey.fallback_to_otp", binder=binder)
		passkey.fallback_to_otp(resp["tmp_id"])

		contents = set(frappe.get_all("Activity Log", filters={"user": user}, pluck="content"))
		self.assertIn(f"passkeys:{notifications.RISK_FALLBACK_USED}", contents)

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
	# compose with core OTP — dispatch, never stack
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
	# 2FA floor — BOTH directions
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
		garbage = {
			"id": "AAAAA",
			"rawId": "AAAAA",
			"response": {"clientDataJSON": b64url(b"{}")},
			"type": "public-key",
		}
		with self.assertRaises(CeremonyExpired):
			self._leg2(resp["tmp_id"], garbage, binder)
		fresh_sid = frappe.local.response.get("state_id")
		self.assertTrue(fresh_sid, "state must be re-armed, not burned, on a garbage id")
		fresh_options = frappe.local.response["verification"]["options"]

		good = self._assert(auth, fresh_options, sign_count=8)
		self._leg2(fresh_sid, good, binder)
		self.assertEqual(frappe.session.user, user)

	def test_malformed_credential_envelope_is_rejected_before_consume(self):
		user = self._user()
		auth = self._enroll(user)
		resp, binder = self._leg1(user, PWD)
		state_id = resp["tmp_id"]
		cases = (
			("encoded null", "null"),
			("encoded list", "[]"),
			("decoded list", []),
			("decoded null", None),
			("invalid JSON", "{"),
			("non-dict response", {"response": 1}),
			("null client data", {"response": {"clientDataJSON": b64url(b"null")}}),
			("list client data", {"response": {"clientDataJSON": b64url(b"[]")}}),
			("scalar client data", {"response": {"clientDataJSON": b64url(b"1")}}),
		)

		for label, malformed in cases:
			with self.subTest(label=label):
				with self.assertRaises(frappe.AuthenticationError) as ctx:
					self._leg2(state_id, malformed, binder)
				self.assertEqual(str(ctx.exception), "Passkey could not be verified.")

		good = self._assert(auth, resp["verification"]["options"], sign_count=8)
		frappe.cache.delete_keys(f"rl::{self._ip}")  # shared empty-cmd rl key in the test harness
		self._leg2(state_id, good, binder)
		self.assertEqual(frappe.session.user, user)

	# ======================================================================
	# the app's plain-password arm seeds a "password" sudo window
	# ======================================================================

	def test_app_plain_password_arm_seeds_password_window(self):
		"""The app's own plain-password arm (a passkey-less, 2FA-less user's
		LDAP-style finish in ``login_with_password``) mints a session whose sudo
		window is classified "password", not "weak". Its endpoint path is not
		/api/method/login, so ``_classify_login_method`` would otherwise mis-seed
		"weak" and re-fire the conditional-create nudge seconds after login."""
		user = self._user()  # no passkey enrolled, no 2FA role → plain finish
		self._leg1(user, PWD)
		self.assertEqual(frappe.session.user, user)
		window = state.get_sudo_window(frappe.session.sid)
		self.assertEqual((window or {}).get("seeded_by"), "password")

	# ======================================================================
	# a failed leg-2 passkey feeds core's LoginAttemptTracker
	# ======================================================================

	def test_failed_second_factor_feeds_login_attempt_tracker(self):
		"""A wrong leg-2 passkey feeds core's LoginAttemptTracker for the resolved
		(leg-1) user, exactly as a bad password would — without leaking user
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
