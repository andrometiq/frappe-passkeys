# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Action-confirmation / "passkey signing" battery on the live bench (DESIGN-v1
§7.2 / §7.3 / §9.3 F19). Drives the full confirm ceremony end to end with the
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
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator

RP_ID = "example.com"
ORIGIN = "https://example.com"
PWD = "Secret_passw0rd_9x!"


def _b64url_decode(value: str) -> bytes:
	import base64

	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ConfirmationTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snap = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.passkey_sign_count_hard_fail = 0
		settings.save(ignore_permissions=True)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		self._ip = frappe.generate_hash(length=12)
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		for field in ("passkey_rp_id", "passkey_origins", "passkey_sign_count_hard_fail"):
			frappe.db.set_single_value("Passkey Settings", field, self._snap.get(field) or 0)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

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

	def _enroll(self, user, seed="c1") -> SoftAuthenticator:
		"""Enroll one real credential for ``user`` (real crypto for verify)."""
		frappe.set_user(user)
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=600)
		self._request("/api/method/passkeys.api.registration.begin_registration")
		begun = registration.begin_registration(flow="explicit")
		auth = SoftAuthenticator(seed=f"{seed}-{self._ip}")
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"], rp_id=RP_ID, origin=ORIGIN, uv=True, credprops_rk=True
		)
		registration.verify_registration(begun["state_id"], credential)
		handle = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
		auth.user_handle = _b64url_decode(handle)
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

	def _assert(self, auth, options, **kw):
		return auth.assertion(challenge_b64=options["challenge"], rp_id=RP_ID, origin=ORIGIN, **kw)

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
		self.assertEqual(begun["options"]["userVerification"], "required")  # §7.2
		self.assertIn("passkey", begun["methods"])
		self.assertEqual(begun["payload_fingerprint"], session.payload_hash({"payment_id": "PAY-1"}))

		credential = self._assert(auth, begun["options"], uv=True, sign_count=5)
		out = self._verify(begun["state_id"], credential)
		token = out["grant"]
		self.assertTrue(token)

		# the grant authorizes exactly this action + payload for this session.
		self._attach_grant(token)
		self.assertTrue(
			session.consume_action_grant(user, "myapp.release_payment", {"payment_id": "PAY-1"})
		)

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
	# grant TTL is the pinned 180 s cap (Redis ex is the sole authority, §4.2)
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

	def test_a_lied_fingerprint_mints_a_grant_the_consumer_rejects(self):
		# A36 correctness contract: echoing a bogus payload_hash only mints a grant
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
	# UV-absent assertion is refused (confirmation requires UV, §7.2)
	# ======================================================================

	def test_uv_absent_assertion_refused(self):
		user = self._user()
		auth = self._enroll(user)
		frappe.set_user(user)
		begun = self._begin("myapp.act", params={"x": 1})
		no_uv = self._assert(auth, begun["options"], uv=False)
		with self.assertRaises(frappe.AuthenticationError):
			self._verify(begun["state_id"], no_uv)

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

	def test_reauth_wrong_password_refused_and_tracked(self):
		user = self._user(with_password=True)
		frappe.set_user(user)
		with self.assertRaises(frappe.AuthenticationError):
			self._reauth("wrong-password")

	def test_reauth_refuses_password_grant_for_passkey_only_action(self):
		# F19: reauth_password will not mint a password grant for an action whose
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
		# is refused by the F19-strict consumer (method must be "passkey").
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
			session.consume_passkey_grant(
				user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": True}
			)
		)

	def test_begin_confirmation_offers_no_password_for_passkey_only_action(self):
		user = self._user()
		self._enroll(user)
		frappe.set_user(user)
		begun = self._begin(session.SET_PASSKEY_ONLY_ACTION, params={"enabled": True})
		self.assertIn("passkey", begun["methods"])
		self.assertNotIn("password", begun["methods"])  # F19 — never a password door
		self.assertNotIn("sudo", begun["methods"])
