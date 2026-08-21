# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Action-confirmation / "passkey signing" battery on the live bench. Drives the
full confirm ceremony end to end with the
soft authenticator — begin_confirmation → UV assertion → verify_confirmation →
single-use grant — and pins the grant-binding invariants (single-use, ≤180 s,
user+sid+action+payload bound, server-computed hash authority, UV-required), the
public ``@passkey_protected`` decorator + 401 retry contract, and the
``reauth_password`` password-fallback reconciliation (improvisation 1)."""

import hashlib
import json

import frappe
from frappe.auth import CookieManager
from frappe.utils import set_request
from frappe.utils.password import update_password

from passkeys import confirm, session, state
from passkeys.api import registration
from passkeys.passkey import CeremonyExpired, PasskeyConfirmationRequired
from passkeys.tests.compat import IntegrationTestCase, WebAuthnAssertMixin, flush_settings_cache
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator, b64url, b64url_decode

RP_ID = "example.com"
ORIGIN = "https://example.com"
PWD = "Secret_passw0rd_9x!"


class ConfirmationTest(WebAuthnAssertMixin, IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snap = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ORIGIN
		settings.passkey_sign_count_hard_fail = 0
		# A login mode must be on for `_enroll`'s begin_registration (gates
		# registration on any-mode-on); confirm.* itself is mode-independent,
		# but enrolling the test credential to confirm with needs a mode. Hermetic —
		# don't depend on ambient Passkey Settings state (mirrors RegistrationCeremonyTest).
		settings.login_with_passkey = 1
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self._ip = frappe.generate_hash(length=12)
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		for field in (
			"login_with_passkey",
			"passkey_rp_id",
			"passkey_origins",
			"passkey_sign_count_hard_fail",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snap.get(field) or 0)
		flush_settings_cache()

	# -- fixtures -----------------------------------------------------------

	@property
	def sid(self) -> str:
		return frappe.session.sid

	def _user(self, *, with_password=False) -> str:
		user = make_user()
		if with_password:
			update_password(user, PWD)
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _enroll(self, user, seed="c1", uv=True) -> SoftAuthenticator:
		"""Enroll one real credential for ``user`` (real crypto for verify).
		``uv=False`` registers a ``uv_initialized=0`` credential (the
		conditional-create-style population)."""
		frappe.set_user(user)
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=600)
		self._request("/api/method/passkeys.api.registration.begin_registration")
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
		auth.user_handle = b64url_decode(handle)
		return auth

	# -- request harness ----------------------------------------------------

	def _request(self, path, *, grant_header=None):
		headers = [("X-Passkey-Grant", grant_header)] if grant_header else None
		set_request(method="POST", path=path, headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.request_ip = self._ip
		frappe.local.form_dict = frappe._dict()
		frappe.local.response = frappe._dict()

	def _begin(self, action, *, params=None, payload_hash=None):
		self._request("/api/method/passkeys.confirm.begin_confirmation")
		return confirm.begin_confirmation(action, params=params, payload_hash=payload_hash)

	def _verify(self, state_id, credential):
		self._request("/api/method/passkeys.confirm.verify_confirmation")
		return confirm.verify_confirmation(state_id, credential)

	def _attach_grant(self, token):
		"""Present a grant token exactly as the client's retry does (header path)."""
		frappe.local.form_dict[session.GRANT_KWARG] = token

	# ======================================================================
	# full round-trip: begin -> get -> verify -> grant
	# ======================================================================

	def test_full_confirmation_round_trip_mints_grant(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)

		begun = self._begin("myapp.release_payment", params={"payment_id": "PAY-1"})
		self.assertEqual(begun["options"]["userVerification"], "required")
		self.assertIn("passkey", begun["methods"])
		self.assertEqual(begun["payload_fingerprint"], session.payload_hash({"payment_id": "PAY-1"}))

		credential = self._assert(auth, begun["options"], uv=True, sign_count=5)
		out = self._verify(begun["state_id"], credential)
		token = out["grant"]
		self.assertTrue(token)

		# the grant authorizes exactly this action + payload for this session.
		self._attach_grant(token)
		self.assertTrue(session.consume_action_grant(user, "myapp.release_payment", {"payment_id": "PAY-1"}))

	def test_malformed_credential_envelope_is_rejected_before_consume(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		good = self._assert(auth, begun["options"], sign_count=5)
		cases = (
			("non-dict response", {"response": 1}),
			("null client data", {"response": {"clientDataJSON": b64url(b"null")}}),
			("list client data", {"response": {"clientDataJSON": b64url(b"[]")}}),
			("scalar client data", {"response": {"clientDataJSON": b64url(b"1")}}),
		)
		for label, malformed in cases:
			with self.subTest(label=label):
				with self.assertRaises(frappe.AuthenticationError) as ctx:
					self._verify(begun["state_id"], malformed)
				self.assertEqual(str(ctx.exception), "Passkey could not be verified.")

		self.assertTrue(self._verify(begun["state_id"], good)["grant"])

	def test_grant_issuance_and_consumption_write_activity_log(self):
		"""Every grant issuance/consumption leaves an Activity Log row —
		routed through notifications._activity_log, not just a logger line."""
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		# verify_confirmation MINTS the grant (a grant_issued row)...
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		# ...then consume it (a grant_consumed row).
		self._attach_grant(token)
		self.assertTrue(session.consume_action_grant(user, "myapp.act", {"x": 1}))
		contents = set(frappe.get_all("Activity Log", filters={"user": user}, pluck="content"))
		self.assertIn("passkeys:grant_issued", contents)
		self.assertIn("passkeys:grant_consumed", contents)

	# ======================================================================
	# grant is single-use
	# ======================================================================

	def test_grant_is_single_use(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]

		self._attach_grant(token)
		self.assertTrue(session.consume_action_grant(user, "myapp.act", {"x": 1}))
		# second use is refused (atomic consume burned it)
		self._attach_grant(token)
		self.assertFalse(session.consume_action_grant(user, "myapp.act", {"x": 1}))

	# ======================================================================
	# grant TTL is the pinned 180 s cap (Redis ex is the sole authority)
	# ======================================================================

	def test_grant_ttl_is_capped_at_180s(self):
		self.assertEqual(state.GRANT_TTL, 180)
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		# the stored key carries a positive TTL <= 180 (never a stored `at` re-derivation)
		key = state._make_key(state.GRANT_PREFIX + hashlib.sha256(token.encode()).hexdigest())
		self.assertTrue(0 < frappe.cache.ttl(key) <= 180)

	# ======================================================================
	# payload + sid + action binding
	# ======================================================================

	def test_grant_does_not_authorize_a_different_action(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("action.A", params={"id": 1})
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		self._attach_grant(token)
		# same session + payload, WRONG action ⇒ refused
		self.assertFalse(session.consume_action_grant(user, "action.B", {"id": 1}))

	def test_grant_does_not_authorize_a_different_payload(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.pay", params={"amount": 100})
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		self._attach_grant(token)
		self.assertFalse(session.consume_action_grant(user, "myapp.pay", {"amount": 200}))

	def test_grant_does_not_authorize_a_different_session(self):
		user = self._user()
		# a grant bound to a foreign sid is unusable from the current session.
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": "some-other-sid",
				"action": "myapp.act",
				"method": "passkey",
				"payload_hash": session.payload_hash({"x": 1}),
			},
		)
		frappe.set_user(user)
		self._request("/api/method/x")
		self._attach_grant(token)
		self.assertFalse(session.consume_action_grant(user, "myapp.act", {"x": 1}))

	# ======================================================================
	# server computes the hash — a client-supplied hash is ignored / rejected
	# ======================================================================

	def test_server_computes_payload_hash_from_raw_params(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		# the client sends RAW params; the fingerprint is the SERVER's canonical hash
		begun = self._begin("myapp.pay", params={"b": 2, "a": 1})
		self.assertEqual(begun["payload_fingerprint"], session.payload_hash({"a": 1, "b": 2}))
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		# the minted grant is bound to that server hash — real kwargs authorize it
		self._attach_grant(token)
		self.assertTrue(session.consume_action_grant(user, "myapp.pay", {"a": 1, "b": 2}))

	def test_params_and_payload_hash_are_mutually_exclusive(self):
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)
		with self.assertRaises(frappe.ValidationError):
			self._begin("myapp.pay", params={"a": 1}, payload_hash="deadbeef")

	def test_confirmation_params_must_be_a_mapping(self):
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)
		for label, malformed in (
			("invalid JSON", "{"),
			("encoded null", "null"),
			("encoded list", "[]"),
			("decoded list", []),
			("decoded scalar", 1),
		):
			with self.subTest(label=label):
				with self.assertRaises(frappe.ValidationError):
					self._begin("myapp.pay", params=malformed)

		begun = self._begin("myapp.pay", params=None)
		self.assertEqual(begun["payload_fingerprint"], session.payload_hash({}))

	def test_a_lied_fingerprint_mints_a_grant_the_consumer_rejects(self):
		# correctness contract: echoing a bogus payload_hash only mints a grant
		# bound to that bogus hash — recomputation from real kwargs refuses it.
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.pay", payload_hash="0" * 64)  # verbatim echo (a lie)
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]
		self._attach_grant(token)
		# the decorator recomputes sha256(canonical_json(real kwargs)) ≠ "000…0"
		self.assertFalse(session.consume_action_grant(user, "myapp.pay", {"amount": 100}))

	# ======================================================================
	# UV-absent assertion is refused (confirmation requires UV)
	# ======================================================================

	def test_uv_absent_assertion_refused(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		no_uv = self._assert(auth, begun["options"], uv=False)
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], no_uv)

	def test_uv_uninitialized_without_password_window_refused_no_grant(self):
		"""Regression (uninitialized-UV row): while
		``uv_initialized=0`` the assertion's UV bit MUST NOT count as a
		verification factor. Without a password-seeded sudo window, the consumed
		ceremony fails terminally and no grant is minted."""
		user = self._user()
		auth = self._enroll(user, seed="uvgate-a", uv=False)
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)  # no password accompanied this session

		begun = self._begin("myapp.act", params={"x": 1})
		credential = self._assert(auth, begun["options"], uv=True)
		with self.assertRaises(frappe.AuthenticationError) as ctx:
			self._verify(begun["state_id"], credential)
		self.assertNotIsInstance(ctx.exception, PasskeyConfirmationRequired)
		self.assertIn("begin again", str(ctx.exception))
		with self.assertRaises(CeremonyExpired):
			self._verify(begun["state_id"], credential)
		# The flag did NOT flip on possession alone (L3 MUST NOT).
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "uv_initialized"), 0)

	def test_uv_uninitialized_with_password_window_flips_and_mints(self):
		"""Regression, the sanctioned path: a password-seeded sudo
		window is the accompanying knowledge factor — the grant mints and
		``uv_initialized`` flips false→true."""
		user = self._user()
		auth = self._enroll(user, seed="uvgate-b", uv=False)
		frappe.set_user(user)
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=600)

		begun = self._begin("myapp.act", params={"x": 1})
		out = self._verify(begun["state_id"], self._assert(auth, begun["options"], uv=True))
		self.assertTrue(out["grant"])
		name = frappe.db.get_value("WebAuthn Credential", {"user": user}, "name")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", name, "uv_initialized"), 1)

	def test_confirm_ceremony_is_single_use(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		credential = self._assert(auth, begun["options"])
		self._verify(begun["state_id"], credential)
		# replay the same state_id ⇒ CeremonyExpired
		with self.assertRaises(CeremonyExpired):
			self._verify(begun["state_id"], credential)

	def test_verify_bound_to_originating_session(self):
		user_a = self._user()
		auth = self._enroll(user_a)
		frappe.set_user(user_a)
		begun = self._begin("myapp.act", params={"x": 1})
		credential = self._assert(auth, begun["options"])
		# a different user cannot spend user_a's ceremony
		user_b = self._user()
		frappe.set_user(user_b)
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], credential)

	# ======================================================================
	# @passkey_protected decorator — the public API surface
	# ======================================================================

	def test_passkey_protected_refused_without_grant(self):
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)

		@confirm.passkey_protected(action="myapp.ship", bind_params=["order"])
		def ship(order=None):
			return {"shipped": order}

		self._request("/api/method/myapp.ship")
		with self.assertRaises(PasskeyConfirmationRequired):
			ship(order="ORD-9")
		# the 401 body carries the SERVER-computed fingerprint for the client to echo
		self.assertEqual(
			frappe.local.response.get("payload_fingerprint"),
			session.payload_hash({"order": "ORD-9"}),
		)
		self.assertEqual(frappe.local.response.get("action"), "myapp.ship")

	def test_decorator_exposes_only_explicit_safe_display_metadata(self):
		user = self._user()
		frappe.set_user(user)

		@confirm.passkey_protected(
			action="myapp.refund",
			bind_params=["payment_id", "internal_note"],
			display_label="Refund payment",
			display_params={"payment_id": "Payment"},
		)
		def refund(payment_id=None, internal_note=None):
			return payment_id, internal_note

		self._request("/api/method/myapp.refund")
		with self.assertRaises(PasskeyConfirmationRequired):
			refund(payment_id="PAY-7", internal_note="never expose this")
		self.assertEqual(frappe.local.response.get("action_label"), "Refund payment")
		self.assertEqual(
			frappe.local.response.get("parameter_summary"),
			[{"label": "Payment", "value": "PAY-7"}],
		)
		self.assertNotIn("never expose this", json.dumps(frappe.local.response))

	def test_action_policy_survives_a_cross_worker_round_trip(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		action = f"myapp.refund.{frappe.generate_hash(length=8)}"
		key = frappe.cache.make_key(confirm._action_policy_key(action))
		self.addCleanup(frappe.cache.delete, key)
		self.addCleanup(confirm._ACTION_POLICIES.pop, action, None)

		@confirm.passkey_protected(
			action=action,
			bind_params=["payment_id"],
			allow_password_fallback=True,
			display_label="Refund payment",
			display_params={"payment_id": "Payment"},
		)
		def refund(payment_id=None):
			return payment_id

		self._request("/api/method/myapp.refund")
		with self.assertRaises(PasskeyConfirmationRequired):
			refund(payment_id="PAY-9")
		fingerprint = frappe.local.response["payload_fingerprint"]

		# Simulate the ceremony landing on a worker that never imported the endpoint.
		confirm._ACTION_POLICIES.pop(action, None)
		begun = self._begin(action, payload_hash=fingerprint)
		self.assertIn("password", begun["methods"])
		self.assertEqual(begun["action_label"], "Refund payment")
		token = self._reauth(PWD, action=action, payload_fingerprint=fingerprint)["grant"]

		self._request("/api/method/myapp.refund", grant_header=token)
		self.assertEqual(refund(payment_id="PAY-9"), "PAY-9")

	def test_unknown_action_policy_fails_closed_without_password_fallback(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		action = f"unknown.action.{frappe.generate_hash(length=8)}"
		begun = self._begin(action, params={})
		self.assertNotIn("password", begun["methods"])
		with self.assertRaises(frappe.AuthenticationError):
			self._reauth(PWD, action=action, payload_fingerprint=begun["payload_fingerprint"])

	def test_display_params_must_be_bound_params(self):
		with self.assertRaises(ValueError):
			confirm.passkey_protected(
				action="myapp.invalid-display",
				bind_params=["payment_id"],
				display_params={"secret": "Secret"},
			)

	def test_passkey_protected_succeeds_and_consumes_grant(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)

		@confirm.passkey_protected(action="myapp.ship", bind_params=["order"])
		def ship(order=None):
			return {"shipped": order}

		begun = self._begin("myapp.ship", params={"order": "ORD-9"})
		token = self._verify(begun["state_id"], self._assert(auth, begun["options"]))["grant"]

		self._request("/api/method/myapp.ship", grant_header=token)
		self.assertEqual(ship(order="ORD-9")["shipped"], "ORD-9")

		# a second call needs a fresh ceremony — the grant was consumed
		self._request("/api/method/myapp.ship", grant_header=token)
		with self.assertRaises(PasskeyConfirmationRequired):
			ship(order="ORD-9")

	# ======================================================================
	# reauth_password reconciliation (improvisation 1)
	# ======================================================================

	def _reauth(self, pwd, *, action=None, payload_fingerprint=None):
		self._request("/api/method/passkeys.confirm.reauth_password")
		return confirm.reauth_password(pwd, action=action, payload_fingerprint=payload_fingerprint)

	def test_reauth_no_action_seeds_sudo_window(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)
		out = self._reauth(PWD)
		self.assertTrue(out.get("seeded"))
		self.assertTrue(session.has_management_sudo(user))

	def test_reauth_with_action_mints_password_grant_for_that_action_only(self):
		user = self._user(with_password=True)
		frappe.set_user(user)

		@confirm.passkey_protected(
			action="myapp.refund", bind_params=["amount"], allow_password_fallback=True
		)
		def refund(amount=None):
			return {"refunded": amount}

		fp = session.payload_hash({"amount": 50})
		token = self._reauth(PWD, action="myapp.refund", payload_fingerprint=fp)["grant"]

		# authorizes myapp.refund with the bound payload...
		self._request("/api/method/myapp.refund", grant_header=token)
		self.assertEqual(refund(amount=50)["refunded"], 50)

		# ...but NOT a different action (mint a fresh one; the first was consumed)
		token2 = self._reauth(PWD, action="myapp.refund", payload_fingerprint=fp)["grant"]
		self._attach_grant(token2)
		self.assertFalse(session.consume_action_grant(user, "myapp.other", {"amount": 50}))

	# ======================================================================
	# fix (a): a completed passkeys.manage confirmation seeds the full-sudo
	# window — the sudo-gated management
	# endpoints check the window, not the grant, so the confirm→retry dance would
	# re-fail without this. Both doors, plus the scoping guard.
	# ======================================================================

	def test_manage_confirmation_passkey_door_seeds_sudo_window(self):
		user = self._user()
		auth = self._enroll(user)  # _enroll leaves a password-seeded window
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)  # go cold
		self.assertFalse(session.has_management_sudo(user))
		begun = self._begin(session.MANAGE_ACTION)
		out = self._verify(begun["state_id"], self._assert(auth, begun["options"], uv=True))
		self.assertIn("grant", out)
		self.assertTrue(session.has_management_sudo(user))  # re-seeded

	def test_manage_confirmation_password_door_seeds_sudo_window(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)
		self.assertFalse(session.has_management_sudo(user))
		out = self._reauth(PWD, action=session.MANAGE_ACTION, payload_fingerprint=session.payload_hash({}))
		self.assertIn("grant", out)
		self.assertTrue(session.has_management_sudo(user))

	def test_non_manage_confirmation_never_seeds_a_management_window(self):
		# scoping: a third-party action confirmation must NOT mint management sudo.
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)
		begun = self._begin("myapp.release_payment", params={"payment_id": "PAY-1"})
		self._verify(begun["state_id"], self._assert(auth, begun["options"], uv=True))
		self.assertFalse(session.has_management_sudo(user))

	def test_reauth_wrong_password_refused_and_tracked(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		self.addCleanup(state.clear_password_failures, user)
		with self.assertRaises(frappe.AuthenticationError):
			self._reauth("wrong-password")
		self.assertEqual(state.get_counter(state.PASSWORD_FAILURE_PREFIX + user), 1)

		self._reauth(PWD)
		self.assertEqual(state.get_counter(state.PASSWORD_FAILURE_PREFIX + user), 0)

	def test_reauth_refuses_password_grant_for_passkey_only_action(self):
		# reauth_password will not mint a password grant for an action whose
		# policy is allow_password_fallback=False (set_passkey_only_login).
		user = self._user(with_password=True)
		frappe.set_user(user)
		with self.assertRaises(frappe.AuthenticationError):
			self._reauth(
				PWD,
				action=session.SET_PASSKEY_ONLY_ACTION,
				payload_fingerprint=session.payload_hash({"enabled": True}),
			)

	def test_f19_password_grant_can_never_satisfy_set_passkey_only(self):
		# even a hand-crafted password-method grant bound perfectly to the action
		# is refused by the strict consumer (method must be "passkey").
		user = self._user(with_password=True)
		frappe.set_user(user)
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": self.sid,
				"action": session.SET_PASSKEY_ONLY_ACTION,
				"method": "password",
				"payload_hash": session.payload_hash({"enabled": True}),
			},
		)
		self._request("/api/method/x")
		frappe.local.form_dict[session.GRANT_KWARG] = token
		self.assertFalse(
			session.consume_passkey_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": True})
		)

	def test_begin_confirmation_offers_no_password_for_passkey_only_action(self):
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)
		begun = self._begin(session.SET_PASSKEY_ONLY_ACTION, params={"enabled": True})
		self.assertIn("passkey", begun["methods"])
		self.assertNotIn("password", begun["methods"])  # never a password door
		self.assertNotIn("sudo", begun["methods"])

	def test_begin_confirmation_hides_password_when_reauth_refuses_it(self):
		user = self._user(with_password=True)
		self._enroll(user, seed="password-method-eligibility")
		frappe.set_user(user)
		original = frappe.db.get_single_value("System Settings", "disable_user_pass_login")

		def set_disable_user_pass_login(value):
			frappe.db.set_single_value("System Settings", "disable_user_pass_login", value)
			frappe.clear_document_cache("System Settings", "System Settings")
			frappe.local.system_settings = None

		self.addCleanup(set_disable_user_pass_login, original)
		set_disable_user_pass_login(1)
		begun = self._begin(session.MANAGE_ACTION, params={})
		self.assertIn("passkey", begun["methods"])
		self.assertNotIn("password", begun["methods"])
		with self.assertRaises(frappe.AuthenticationError):
			self._reauth(
				PWD,
				action=session.MANAGE_ACTION,
				payload_fingerprint=begun["payload_fingerprint"],
			)

	# ======================================================================
	# the confirm assertion options carry a wire timeout equal to
	# THIS ceremony's server-side TTL, not the engine's 300 s default
	# ======================================================================

	def test_begin_confirmation_wire_timeout_matches_ceremony_ttl(self):
		"""begin_confirmation's assertion options carry a browser wire
		timeout equal to the server-side ceremony TTL (state.CONFIRM_CEREMONY_TTL =
		180 s), NOT the engine's 300 s default — otherwise a slow hybrid cross-device
		confirmation (3-5 min) clears the browser gesture only to fail server-side on
		the already-expired ceremony. Login/registration ceremonies keep the 300 s
		default because their store_ceremony TTL is the matching 300 s CEREMONY_TTL."""
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		self.assertEqual(begun["options"]["timeout"], 180000)
		self.assertEqual(begun["options"]["timeout"], state.CONFIRM_CEREMONY_TTL * 1000)

	# ======================================================================
	# grant user-binding is independent of sid-binding (record.user == user)
	# ======================================================================

	def test_grant_wrong_user_same_sid_is_refused(self):
		"""Session consume path (record.user == user): a grant forged for user A
		cannot be consumed as user B even on the SAME sid — the user binding is not a
		by-product of the sid binding. Positive control: the same shape consumed as A
		on that identical sid succeeds, isolating the refusal to the user check."""
		user_a = self._user()
		user_b = self._user()
		frappe.set_user(user_a)
		self._request("/api/method/x")
		sid = self.sid  # the one live sid both the grants and the consumes see

		def _seed(owner):
			token = frappe.generate_hash()
			state.store_grant(
				hashlib.sha256(token.encode()).hexdigest(),
				{
					"v": 1,
					"user": owner,
					"sid": sid,
					"action": "myapp.act",
					"method": "passkey",
					"payload_hash": session.payload_hash({"x": 1}),
				},
			)
			return token

		# forged for user_a, consumed as user_b on the SAME sid → refused (user binding)
		self._attach_grant(_seed(user_a))
		self.assertFalse(session.consume_action_grant(user_b, "myapp.act", {"x": 1}))
		# positive control: the identical grant on that identical sid consumes True for
		# its real owner — proving it was the user binding, not the sid, that refused B.
		self._attach_grant(_seed(user_a))
		self.assertTrue(session.consume_action_grant(user_a, "myapp.act", {"x": 1}))

	# ======================================================================
	# A matched grant whose method the policy rejects is BURNED,
	# not merely refused (session.consume_action_grant)
	# ======================================================================

	def test_password_grant_burned_on_method_mismatch(self):
		"""session.consume_action_grant: a password-method grant that
		matches action+payload but whose method the action policy rejects
		(allow_password_fallback=False) is BURNED on the refused consume — the single-
		use consume runs before the policy check (one gesture = one attempt). Proven by
		a second consume of the same token failing even with allow_password_fallback=
		True (which would accept a LIVE password grant) — the token is gone."""
		user = self._user()
		frappe.set_user(user)
		self._request("/api/method/x")
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": self.sid,
				"action": "myapp.refund",
				"method": "password",
				"payload_hash": session.payload_hash({"amount": 50}),
			},
		)
		# matched action+payload+method=password, but the policy forbids a password
		# grant here → refused AND burned (consume ran before the policy check).
		self._attach_grant(token)
		self.assertFalse(
			session.consume_action_grant(user, "myapp.refund", {"amount": 50}, allow_password_fallback=False)
		)
		# the token is gone: a retry that WOULD have accepted a live password grant
		# (allow_password_fallback=True) still fails — burn, not a mere policy refusal.
		self._attach_grant(token)
		self.assertFalse(
			session.consume_action_grant(user, "myapp.refund", {"amount": 50}, allow_password_fallback=True)
		)

	# ======================================================================
	# reauth_password consults the per-user password-oracle throttle
	# ======================================================================

	def test_reauth_password_refuses_when_password_throttled(self):
		"""confirm.reauth_password: the endpoint checks the per-user
		password-oracle throttle before touching the password. With the failure counter
		already at the limit, a reauth attempt is refused THROTTLED — even with the
		CORRECT password, never a password-oracle read. (test_state pins the counter's
		climb; this pins endpoint enforcement.)"""
		user = self._user(with_password=True)
		frappe.set_user(user)
		self.addCleanup(state.clear_password_failures, user)
		for _ in range(state.PASSWORD_FAILURE_LIMIT):
			state.record_password_failure(user)
		self.assertTrue(state.is_password_throttled(user))

		with self.assertRaises(frappe.AuthenticationError) as ctx:
			self._reauth(PWD)  # the CORRECT password — still refused because throttled
		self.assertIn("Too many attempts", str(ctx.exception))

	def test_reauth_password_allows_limit_then_throttles_limit_plus_one(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		self.addCleanup(state.clear_password_failures, user)
		for _ in range(state.PASSWORD_FAILURE_LIMIT - 1):
			state.claim_password_attempt(user)

		with self.assertRaisesRegex(frappe.AuthenticationError, "password didn't match"):
			self._reauth("wrong-password")
		self.assertEqual(
			state.get_counter(state.PASSWORD_FAILURE_PREFIX + user),
			state.PASSWORD_FAILURE_LIMIT,
		)

		with self.assertRaisesRegex(frappe.AuthenticationError, "Too many attempts"):
			self._reauth(PWD)
