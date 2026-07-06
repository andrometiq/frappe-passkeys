# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Credential-management endpoints on the live bench (DESIGN-v1 §8, §9.3,
§12.2, §12.5): ownership / uniform-not-found (no cross-user IDOR), sudo-gated
delete, the last-credential guard for passkey-only users, rename validation,
and the F19 passkey-grant-only ``set_passkey_only_login`` gate."""

import hashlib

import frappe

from passkeys import session, state
from passkeys.api import credentials
from passkeys.passkey import PasskeyConfirmationRequired
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class CredentialManagementTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")

	@property
	def sid(self) -> str:
		# frappe.set_user() sets session.sid = username; read it live.
		return frappe.session.sid

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _seed_sudo(self, user, seeded_by="password"):
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": seeded_by}, ttl=600)

	def _seed_grant(self, user, action, params, method="passkey"):
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": self.sid,
				"action": action,
				"method": method,
				"payload_hash": session.payload_hash(params),
			},
		)
		frappe.local.form_dict[session.GRANT_KWARG] = token

	# ---- list + ownership (§8.2, §3.0) ------------------------------------

	def test_list_returns_only_own_credentials(self):
		user_a, user_b = self._user(), self._user()
		cred_a = make_credential(user_a, label="A key")
		cred_b = make_credential(user_b, label="B key")
		frappe.set_user(user_a)
		names = [row["name"] for row in credentials.list_credentials()["credentials"]]
		self.assertIn(cred_a.name, names)
		self.assertNotIn(cred_b.name, names)

	# ---- rename (§8.2 — display-only, no sudo) ----------------------------

	def test_rename_happy_path(self):
		user = self._user()
		cred = make_credential(user, label="Old")
		frappe.set_user(user)
		result = credentials.rename_credential(cred.name, "My Laptop")
		self.assertEqual(result["label"], "My Laptop")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", cred.name, "label"), "My Laptop")

	def test_rename_rejects_empty_label(self):
		user = self._user()
		cred = make_credential(user)
		frappe.set_user(user)
		with self.assertRaises(frappe.ValidationError):
			credentials.rename_credential(cred.name, "   ")

	def test_rename_sanitizes_label(self):
		user = self._user()
		cred = make_credential(user)
		frappe.set_user(user)
		credentials.rename_credential(cred.name, "<b>Phone</b>")
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", cred.name, "label"), "Phone")

	def test_rename_cross_user_is_uniform_not_found(self):
		user_a, user_b = self._user(), self._user()
		cred_b = make_credential(user_b)
		frappe.set_user(user_a)
		with self.assertRaises(frappe.DoesNotExistError):
			credentials.rename_credential(cred_b.name, "hijack")

	def test_rename_missing_name_is_uniform_not_found(self):
		user = self._user()
		frappe.set_user(user)
		with self.assertRaises(frappe.DoesNotExistError):
			credentials.rename_credential("nonexistent-credential", "x")

	# ---- delete: sudo gate + ownership + last-credential guard -------------

	def test_delete_requires_sudo_window(self):
		user = self._user()
		make_credential(user)
		frappe.set_user(user)
		state.clear_sudo_window(self.sid)
		with self.assertRaises(PasskeyConfirmationRequired):
			credentials.delete_credential(make_credential(user).name)

	def test_delete_happy_path_with_sudo(self):
		user = self._user()
		keep = make_credential(user, label="keep")
		drop = make_credential(user, label="drop")
		frappe.set_user(user)
		self._seed_sudo(user)
		credentials.delete_credential(drop.name)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", drop.name))
		self.assertTrue(frappe.db.exists("WebAuthn Credential", keep.name))

	def test_delete_cross_user_is_uniform_not_found(self):
		user_a, user_b = self._user(), self._user()
		cred_b = make_credential(user_b)
		frappe.set_user(user_a)
		self._seed_sudo(user_a)
		with self.assertRaises(frappe.DoesNotExistError):
			credentials.delete_credential(cred_b.name)
		# untouched — a foreign delete never mutated B's row
		self.assertTrue(frappe.db.exists("WebAuthn Credential", cred_b.name))

	def test_delete_last_credential_of_passkey_only_user_refused(self):
		user = self._user()
		only = make_credential(user)
		make_handle(user, passkey_only_login=1)  # handle floor allows: 1 enabled credential
		frappe.set_user(user)
		self._seed_sudo(user)
		with self.assertRaises(frappe.ValidationError):
			credentials.delete_credential(only.name)
		self.assertTrue(frappe.db.exists("WebAuthn Credential", only.name))

	def test_delete_non_last_credential_of_passkey_only_user_allowed(self):
		user = self._user()
		make_credential(user, label="one")
		two = make_credential(user, label="two")
		make_handle(user, passkey_only_login=1)
		frappe.set_user(user)
		self._seed_sudo(user)
		credentials.delete_credential(two.name)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", two.name))

	# ---- set_passkey_only_login (§9.3 / F19) — passkey grant only ----------

	def test_set_passkey_only_refused_without_grant(self):
		user = self._user()
		make_credential(user)
		make_credential(user)
		frappe.set_user(user)
		with self.assertRaises(PasskeyConfirmationRequired):
			credentials.set_passkey_only_login(1)
		# passkey-grade only — no password / sudo fallback is offered
		self.assertEqual(frappe.local.response.get("methods"), ["passkey"])

	def test_set_passkey_only_refused_with_only_a_sudo_window(self):
		user = self._user()
		make_credential(user)
		make_credential(user)
		frappe.set_user(user)
		# a password-seeded sudo window must NOT satisfy the flag toggle (§9.3)
		self._seed_sudo(user, seeded_by="password")
		with self.assertRaises(PasskeyConfirmationRequired):
			credentials.set_passkey_only_login(1)

	def test_set_passkey_only_enable_requires_two_passkeys(self):
		user = self._user()
		make_credential(user)  # only one
		frappe.set_user(user)
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": True})
		with self.assertRaises(frappe.ValidationError):
			credentials.set_passkey_only_login(1)

	def test_set_passkey_only_enable_with_grant_and_two_passkeys(self):
		user = self._user()
		make_credential(user)
		make_credential(user)
		make_handle(user)  # registration mints the handle; the flag lives on it
		frappe.set_user(user)
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": True})
		result = credentials.set_passkey_only_login(1)
		self.assertEqual(result["passkey_only_login"], 1)

	def test_set_passkey_only_disable_with_grant(self):
		user = self._user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)
		frappe.set_user(user)
		self._seed_grant(user, session.SET_PASSKEY_ONLY_ACTION, {"enabled": False})
		result = credentials.set_passkey_only_login(0)
		self.assertEqual(result["passkey_only_login"], 0)

	def test_set_passkey_only_end_to_end_grant_matches_the_401_fingerprint(self):
		"""C2 (E2E): the 401 the toggle raises must carry the SAME payload fingerprint
		the retry's consume recomputes — a passkey grant minted from that fingerprint
		verbatim (exactly what begin_confirmation's echo + verify_confirmation produce)
		must then satisfy the retry. The bug shipped a None fingerprint, so the grant
		could never match and the toggle could NEVER succeed end to end. Both directions."""
		for enabled, want in ((1, 1), (0, 0)):
			user = self._user()
			make_credential(user)
			make_credential(user)  # ≥2 enabled (the enable-direction floor)
			make_handle(user, passkey_only_login=(0 if enabled else 1))
			frappe.set_user(user)
			frappe.local.form_dict = frappe._dict()
			frappe.local.response = frappe._dict()

			# 1) no grant → 401 carrying the SERVER-computed fingerprint of THIS payload
			with self.assertRaises(PasskeyConfirmationRequired):
				credentials.set_passkey_only_login(enabled)
			fingerprint = frappe.local.response.get("payload_fingerprint")
			self.assertEqual(fingerprint, session.payload_hash({"enabled": bool(enabled)}))

			# 2) mint a passkey grant bound to that fingerprint verbatim
			token = frappe.generate_hash()
			state.store_grant(
				hashlib.sha256(token.encode()).hexdigest(),
				{
					"v": 1,
					"user": user,
					"sid": self.sid,
					"action": session.SET_PASSKEY_ONLY_ACTION,
					"method": "passkey",
					"payload_hash": fingerprint,
				},
			)
			frappe.local.form_dict[session.GRANT_KWARG] = token

			# 3) retry with the grant → the toggle persists
			result = credentials.set_passkey_only_login(enabled)
			self.assertEqual(result["passkey_only_login"], want)

	def test_list_credentials_carries_passkey_only_login_flag(self):
		"""C2-payload-exposure: the client reads passkey_only_login from the list
		payload — it must be present and reflect a flip."""
		user = self._user()
		make_credential(user)
		make_handle(user, passkey_only_login=0)
		frappe.set_user(user)
		self.assertEqual(credentials.list_credentials()["passkey_only_login"], 0)
		frappe.db.set_value("WebAuthn User Handle", {"user": user}, "passkey_only_login", 1)
		self.assertEqual(credentials.list_credentials()["passkey_only_login"], 1)

	def test_authed_rate_limit_is_per_user(self):
		"""S4 (§3.0): an authed endpoint driven past its per-user limit 429s; a
		different user is unaffected (the limit keys on frappe.session.user)."""
		user_a, user_b = self._user(), self._user()
		make_credential(user_a)
		make_credential(user_b)
		frappe.set_user(user_a)
		for _ in range(60):  # list_credentials is 60/min/user (§3.0 row 9)
			credentials.list_credentials()
		with self.assertRaises(frappe.TooManyRequestsError):
			credentials.list_credentials()
		# a different user has their own counter — unaffected
		frappe.set_user(user_b)
		self.assertIn("credentials", credentials.list_credentials())
