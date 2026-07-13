# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Registration ceremony round-trip on the live bench:
begin issues options + caches the challenge; complete verifies + persists a
credential row; the challenge is single-use; duplicate / cross-account
credential ids are refused; registration is sudo-gated."""

import frappe

from passkeys import state
from passkeys.api import registration
from passkeys.passkey import CeremonyExpired, PasskeyConfirmationRequired
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator

RP_ID = "example.com"
ORIGIN = "https://example.com"


class RegistrationCeremonyTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore_settings)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore_settings(self):
		for field in ("login_with_passkey", "passkey_as_second_factor", "passkey_rp_id", "passkey_origins"):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or 0)
		flush_settings_cache()

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _seed_sudo(self, user, seeded_by="password"):
		state.set_sudo_window(frappe.session.sid, {"user": user, "seeded_by": seeded_by}, ttl=600)

	def _register(self, user, seed="primary", seeded_by="password", flow="explicit"):
		frappe.set_user(user)
		self._seed_sudo(user, seeded_by)
		begun = registration.begin_registration(flow=flow)
		auth = SoftAuthenticator(seed=seed)
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"], rp_id=RP_ID, origin=ORIGIN, credprops_rk=True
		)
		return begun, credential, auth

	# ---- happy path -------------------------------------------------------

	def test_full_round_trip_persists_credential(self):
		user = self._user()
		begun, credential, _auth = self._register(user)
		self.assertIn("state_id", begun)
		self.assertEqual(begun["options"]["rp"]["id"], RP_ID)

		result = registration.verify_registration(begun["state_id"], credential)
		row = frappe.get_doc("WebAuthn Credential", result["name"])
		self.assertEqual(row.user, user)
		self.assertEqual(row.credential_id, credential["id"])
		self.assertEqual(row.sign_count, 0)
		self.assertEqual(row.uv_initialized, 1)  # ceremony UV bit
		self.assertEqual(row.discoverable, "Yes")  # credProps.rk=true
		self.assertTrue(row.public_key)
		self.assertEqual(result["signal"]["credential_ids"], [credential["id"]])
		# a WebAuthn User Handle was minted lazily
		self.assertTrue(frappe.db.exists("WebAuthn User Handle", {"user": user}))

	def test_challenge_is_single_use(self):
		user = self._user()
		begun, credential, _auth = self._register(user)
		registration.verify_registration(begun["state_id"], credential)
		# the store row is consumed — a replay of the same state fails closed
		with self.assertRaises(CeremonyExpired):
			registration.verify_registration(begun["state_id"], credential)
		# ...while the reusable sudo window still holds (store invariants)
		self.assertIsNotNone(state.get_sudo_window(frappe.session.sid))

	def test_duplicate_credential_id_rejected(self):
		user = self._user()
		begun, credential, _auth = self._register(user)
		registration.verify_registration(begun["state_id"], credential)
		# a second ceremony, same authenticator (same credential id) → refused
		begun2, credential2, _ = self._register(user, seed="primary")
		with self.assertRaises(frappe.AuthenticationError):
			registration.verify_registration(begun2["state_id"], credential2)

	def test_cross_account_credential_id_rejected(self):
		user_a = self._user()
		begun_a, credential_a, _ = self._register(user_a)
		registration.verify_registration(begun_a["state_id"], credential_a)

		# user B attempts to register the SAME credential id (hijack) → refused
		user_b = self._user()
		begun_b, credential_b, _ = self._register(user_b, seed="primary")
		self.assertEqual(credential_b["id"], credential_a["id"])
		with self.assertRaises(frappe.AuthenticationError):
			registration.verify_registration(begun_b["state_id"], credential_b)

	# ---- sudo gating -------------------------------------------------

	def test_registration_requires_sudo_window(self):
		user = self._user()
		frappe.set_user(user)
		state.clear_sudo_window(frappe.session.sid)
		# a hijacked session with no fresh re-auth cannot mint a passwordless credential
		with self.assertRaises(PasskeyConfirmationRequired):
			registration.begin_registration(flow="explicit")

	def test_conditional_create_requires_password_seeded_window(self):
		user = self._user()
		frappe.set_user(user)
		# a passkey-seeded window is NOT the just-typed-password freshness proof
		self._seed_sudo(user, seeded_by="passkey")
		with self.assertRaises(PasskeyConfirmationRequired):
			registration.begin_registration(flow="conditional_create")
		# a password-seeded window lets the silent upgrade proceed
		self._seed_sudo(user, seeded_by="password")
		begun = registration.begin_registration(flow="conditional_create")
		self.assertIn("state_id", begun)
		self.assertEqual(begun["options"]["authenticatorSelection"]["residentKey"], "preferred")

	def test_weak_login_bootstrap_allows_only_first_enrollment(self):
		"""Weak-login bootstrap, BOTH directions: a weak-seeded window
		(email-link / OAuth / social class) authorizes ONLY a first explicit
		enrollment (zero existing credentials) and records the risk event; the
		moment the user holds ≥1 credential the SAME weak window is refused —
		management-grade (password/passkey/reauth) sudo is then required. A recovery
		login must never silently mint general enrollment power."""
		user = self._user()
		frappe.set_user(user)
		# the allow knob defaults on; pin it explicitly + restore (setUp does not).
		self.addCleanup(flush_settings_cache)
		self.addCleanup(
			frappe.db.set_single_value,
			"Passkey Settings",
			"passkey_allow_first_enrollment_on_weak_login",
			self._snapshot.get("passkey_allow_first_enrollment_on_weak_login") or 0,
		)
		frappe.db.set_single_value("Passkey Settings", "passkey_allow_first_enrollment_on_weak_login", 1)
		flush_settings_cache()

		# direction 1 — zero credentials + weak window → first enrollment is allowed,
		# and the weak-login-bootstrap risk event is recorded.
		self._seed_sudo(user, seeded_by="weak")
		before = frappe.db.count("Activity Log", {"user": user})
		begun = registration.begin_registration(flow="explicit")
		self.assertIn("state_id", begun)
		self.assertGreater(frappe.db.count("Activity Log", {"user": user}), before)
		contents = set(frappe.get_all("Activity Log", filters={"user": user}, pluck="content"))
		self.assertIn("passkeys:weak_login_enrollment", contents)

		# persist that first credential so the user now holds ≥1 enabled passkey
		auth = SoftAuthenticator(seed="weak-bootstrap")
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"], rp_id=RP_ID, origin=ORIGIN, credprops_rk=True
		)
		registration.verify_registration(begun["state_id"], credential)

		# direction 2 — with ≥1 credential the SAME weak window no longer bootstraps:
		# a second enrollment demands management-grade sudo.
		self._seed_sudo(user, seeded_by="weak")
		with self.assertRaises(PasskeyConfirmationRequired):
			registration.begin_registration(flow="explicit")

	def test_weak_login_bootstrap_refused_when_knob_off(self):
		"""Even a first enrollment is refused from a weak window when
		``passkey_allow_first_enrollment_on_weak_login`` is off — the bootstrap is an
		opt-in allowance, not a default."""
		user = self._user()
		frappe.set_user(user)
		self.addCleanup(flush_settings_cache)
		self.addCleanup(
			frappe.db.set_single_value,
			"Passkey Settings",
			"passkey_allow_first_enrollment_on_weak_login",
			self._snapshot.get("passkey_allow_first_enrollment_on_weak_login") or 0,
		)
		frappe.db.set_single_value("Passkey Settings", "passkey_allow_first_enrollment_on_weak_login", 0)
		flush_settings_cache()

		self._seed_sudo(user, seeded_by="weak")
		with self.assertRaises(PasskeyConfirmationRequired):
			registration.begin_registration(flow="explicit")

	def test_explicit_flow_requests_resident_key_required(self):
		user = self._user()
		begun, _credential, _auth = self._register(user)
		self.assertEqual(begun["options"]["authenticatorSelection"]["residentKey"], "required")

	def test_explicit_flow_without_credprops_stores_discoverable_yes(self):
		"""An explicit-flow success with NO credProps (Safari ships none) still
		stored a discoverable credential — the flow pins residentKey="required", so
		``discoverable`` must be "Yes" even though ``result.discoverable`` is
		"Unknown". Before the fix it stored "Unknown"."""
		user = self._user()
		frappe.set_user(user)
		self._seed_sudo(user, "password")
		begun = registration.begin_registration(flow="explicit")
		auth = SoftAuthenticator(seed="s11-no-credprops")
		credential = auth.registration(
			challenge_b64=begun["options"]["challenge"], rp_id=RP_ID, origin=ORIGIN
		)  # credprops_rk defaults to None → clientExtensionResults == {}
		self.assertEqual(credential["clientExtensionResults"], {})  # sanity: Safari case
		result = registration.verify_registration(begun["state_id"], credential)
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", result["name"], "discoverable"), "Yes")
