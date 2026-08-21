# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""P1 battery: DocType schemas, validator guards, Passkey Settings policy."""

from unittest.mock import patch

import frappe

from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class PasskeyTestCase(IntegrationTestCase):
	def make_user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def enable_passkey_login_mode(self) -> None:
		"""Establish the production invariant required by passkey-only handles."""
		previous = frappe.db.get_single_value("Passkey Settings", "login_with_passkey")
		self.addCleanup(
			frappe.db.set_single_value,
			"Passkey Settings",
			"login_with_passkey",
			previous or 0,
		)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)


class TestDocTypeSchemas(PasskeyTestCase):
	def test_doctypes_installed(self):
		self.assertTrue(frappe.db.table_exists("WebAuthn Credential"))
		self.assertTrue(frappe.db.table_exists("WebAuthn User Handle"))
		self.assertTrue(frappe.get_meta("Passkey Settings").issingle)

	def test_credential_schema(self):
		meta = frappe.get_meta("WebAuthn Credential")
		self.assertEqual(meta.autoname, "hash")
		self.assertTrue(meta.track_changes)
		self.assertTrue(meta.get_field("credential_id_sha256").unique)
		self.assertEqual(meta.get_field("sign_count").fieldtype, "Long Int")
		self.assertEqual(meta.get_field("credential_id").fieldtype, "Long Text")
		self.assertEqual(meta.get_field("discoverable").default, "Unknown")
		# permissions philosophy: no role gets create
		self.assertFalse(any(perm.get("create") for perm in meta.permissions))
		roles = {perm.role for perm in meta.permissions}
		self.assertEqual(roles, {"System Manager"})

	def test_user_handle_schema(self):
		meta = frappe.get_meta("WebAuthn User Handle")
		self.assertEqual(meta.autoname, "hash")
		self.assertTrue(meta.get_field("user").unique)
		self.assertTrue(meta.get_field("handle").unique)
		self.assertFalse(any(perm.get("create") or perm.get("delete") for perm in meta.permissions))

	def test_settings_defaults(self):
		meta = frappe.get_meta("Passkey Settings")
		for fieldname, default in (
			("login_with_passkey", "0"),
			("passkey_as_second_factor", "0"),
			("passkey_2fa_allow_otp_fallback", "1"),
			("passkey_sign_count_hard_fail", "0"),
			("passkey_max_per_user", "10"),
			("passkey_reauth_window", "600"),
			("passkey_allow_first_enrollment_on_weak_login", "1"),
			("passkey_enrollment_policy", "Nudge"),
			("passkey_nudge_max_prompts", "3"),
			("passkey_nudge_cooldown_days", "30"),
			("passkey_conditional_create", "1"),
			("passkey_enforce_scope", "All Users"),
			("passkey_enforce_grace_logins", "3"),
			("passkey_enforce_incapable", "Degrade to Nudge"),
			("passkey_enforce_allow_hybrid", "1"),
			("passkey_notify_on_change", "1"),
			("passkey_notify_password_fallback", "0"),
		):
			self.assertEqual(meta.get_field(fieldname).default, default, fieldname)
		# install persisted the defaults with all modes OFF
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_max_per_user"), 10)
		self.assertEqual(frappe.db.get_single_value("Passkey Settings", "passkey_reauth_window"), 600)


class TestWebAuthnCredential(PasskeyTestCase):
	def test_credential_id_sha256_globally_unique(self):
		user = self.make_user()
		credential = make_credential(user)
		other_user = self.make_user()
		with self.assertRaises((frappe.UniqueValidationError, frappe.DuplicateEntryError)):
			make_credential(other_user, credential_id_sha256=credential.credential_id_sha256)

	def test_label_is_sanitized_and_capped(self):
		user = self.make_user()
		credential = make_credential(user, label="<script>alert(1)</script>My Key")
		self.assertNotIn("<", credential.label)
		self.assertIn("My Key", credential.label)

		credential.label = "x" * 400
		credential.save()
		self.assertEqual(len(credential.label), 140)

	def test_backup_eligible_is_write_once(self):
		credential = make_credential(self.make_user())
		credential.backup_eligible = 1
		self.assertRaises(frappe.ValidationError, credential.save)

	def test_credential_identity_is_immutable_but_runtime_updates_still_work(self):
		credential = make_credential(self.make_user(), label="Original", sign_count=3)
		for field, value in (
			("user", self.make_user()),
			("credential_id", "tampered-credential-id"),
			("credential_id_sha256", "0" * 64),
			("public_key", "tampered-public-key"),
		):
			with self.subTest(field=field):
				credential.reload()
				setattr(credential, field, value)
				with self.assertRaises(frappe.ValidationError):
					credential.save()

		credential.reload()
		credential.label = "Renamed"
		credential.save()
		self.assertEqual(frappe.db.get_value(credential.doctype, credential.name, "label"), "Renamed")

		frappe.db.set_value(credential.doctype, credential.name, "sign_count", 9, update_modified=False)
		self.assertEqual(frappe.db.get_value(credential.doctype, credential.name, "sign_count"), 9)

	def test_sign_count_never_regresses(self):
		credential = make_credential(self.make_user(), sign_count=10)
		credential.sign_count = 5
		self.assertRaises(frappe.ValidationError, credential.save)

		credential.reload()
		credential.sign_count = 11
		credential.save()
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", credential.name, "sign_count"), 11)


class TestWebAuthnUserHandle(PasskeyTestCase):
	def setUp(self):
		super().setUp()
		self.enable_passkey_login_mode()

	def test_handle_identity_is_immutable(self):
		handle = make_handle(self.make_user())

		handle.handle = "tampered-handle-value"
		self.assertRaises(frappe.ValidationError, handle.save)

		handle.reload()
		handle.user = self.make_user()
		self.assertRaises(frappe.ValidationError, handle.save)

	def test_passkey_only_login_requires_enabled_credential(self):
		user = self.make_user()
		handle = make_handle(user)

		# no credential at all → refused
		handle.passkey_only_login = 1
		self.assertRaises(frappe.ValidationError, handle.save)

		# a disabled credential does not count
		credential = make_credential(user, enabled=0)
		handle.reload()
		handle.passkey_only_login = 1
		self.assertRaises(frappe.ValidationError, handle.save)

		# an enabled credential satisfies the floor
		credential.reload()
		credential.enabled = 1
		credential.save()
		handle.reload()
		handle.passkey_only_login = 1
		handle.save()
		self.assertTrue(frappe.db.get_value("WebAuthn User Handle", handle.name, "passkey_only_login"))

	def test_floor_binds_at_insert_too(self):
		user = self.make_user()
		self.assertRaises(frappe.ValidationError, make_handle, user, passkey_only_login=1)

	def test_user_trash_cascades(self):
		user = self.make_user()
		make_credential(user)
		make_handle(user)
		default_keys = (
			f"{user}_passkey_nudge",
			f"{user}_passkey_enforce",
			f"{user}_passkey_incapable_notified",
		)
		for key in default_keys:
			frappe.db.set_default(key, "sentinel", parent=DEFAULTS_PARENT)
			self.assertEqual(frappe.db.get_default(key, parent=DEFAULTS_PARENT), "sentinel")

		frappe.delete_doc("User", user, force=1, ignore_permissions=True)

		self.assertFalse(frappe.db.exists("WebAuthn Credential", {"user": user}))
		self.assertFalse(frappe.db.exists("WebAuthn User Handle", {"user": user}))
		for key in default_keys:
			self.assertIsNone(frappe.db.get_default(key, parent=DEFAULTS_PARENT))


class TestPasskeySettingsValidation(PasskeyTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self._two_factor_auth = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		self._disable_user_pass_login = frappe.db.get_single_value(
			"System Settings", "disable_user_pass_login"
		)
		self._conf_host_name = frappe.local.conf.get("host_name")
		self._conf_developer_mode = frappe.local.conf.get("developer_mode")
		self._conf_encryption_key = frappe.local.conf.get("encryption_key")

	def tearDown(self):
		from frappe.utils import cint

		for field in ("login_with_passkey", "passkey_as_second_factor"):
			frappe.db.set_single_value("Passkey Settings", field, cint(self._snapshot.get(field)))
		for field in ("passkey_rp_id", "passkey_origins", "passkey_app_origins"):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or "")
		frappe.db.set_single_value(
			"Passkey Settings", "passkey_reauth_window", self._snapshot.get("passkey_reauth_window")
		)
		frappe.local.conf["host_name"] = self._conf_host_name
		frappe.local.conf["developer_mode"] = self._conf_developer_mode
		frappe.local.conf["encryption_key"] = self._conf_encryption_key
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", cint(self._two_factor_auth))
		frappe.db.set_single_value(
			"System Settings", "disable_user_pass_login", cint(self._disable_user_pass_login)
		)
		super().tearDown()

	def _settings(self, **values):
		doc = frappe.get_doc("Passkey Settings")
		doc.update(values)
		return doc

	def test_enable_requires_resolvable_rp_id(self):
		frappe.local.conf["host_name"] = None
		doc = self._settings(login_with_passkey=1, passkey_rp_id="")
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_rp_id_resolves_from_host_name(self):
		from passkeys import policy

		frappe.local.conf["host_name"] = "https://site.example.com"
		doc = self._settings(login_with_passkey=1, passkey_rp_id="", passkey_origins="")
		self.assertEqual(policy.resolve_rp_id(doc), "site.example.com")
		doc.save()
		self.assertTrue(frappe.db.get_single_value("Passkey Settings", "login_with_passkey"))

	def test_explicit_rp_id_must_be_bare_host(self):
		doc = self._settings(login_with_passkey=1, passkey_rp_id="https://example.com")
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_enable_refuses_without_webauthn(self):
		doc = self._settings(
			login_with_passkey=1,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		with patch("passkeys.policy.webauthn_available", return_value=False):
			self.assertRaises(frappe.ValidationError, doc.save)

	def test_explicit_rp_id_does_not_implicitly_trust_its_apex(self):
		frappe.local.conf["host_name"] = "https://other.test"
		doc = self._settings(login_with_passkey=1, passkey_rp_id="example.com", passkey_origins="")
		with self.assertRaises(frappe.ValidationError):
			doc.save()

	def test_origins_must_be_https(self):
		doc = self._settings(
			login_with_passkey=1, passkey_rp_id="example.com", passkey_origins="http://sub.example.com"
		)
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_origin_must_be_exact_origin_without_userinfo_or_path(self):
		for origin in ("https://user@example.com", "https://example.com/"):
			with self.subTest(origin=origin):
				doc = self._settings(
					login_with_passkey=1,
					passkey_rp_id="example.com",
					passkey_origins=origin,
				)
				with self.assertRaises(frappe.ValidationError):
					doc.save()

	def test_invalid_origins_are_rejected_with_both_modes_off(self):
		frappe.local.conf["host_name"] = None
		for values in (
			{"passkey_origins": "https://example.com/path", "passkey_app_origins": ""},
			{"passkey_origins": "", "passkey_app_origins": "android:apk-key-hash:bad"},
		):
			with self.subTest(values=values):
				doc = self._settings(
					login_with_passkey=0,
					passkey_as_second_factor=0,
					passkey_rp_id="",
					**values,
				)
				with self.assertRaises(frappe.ValidationError):
					doc.save()

	def test_valid_origins_save_with_both_modes_off_and_no_rp_id(self):
		frappe.local.conf["host_name"] = None
		doc = self._settings(
			login_with_passkey=0,
			passkey_as_second_factor=0,
			passkey_rp_id="",
			passkey_origins="https://example.com",
			passkey_app_origins=f"android:apk-key-hash:{'A' * 43}",
		)
		doc.save()

	def test_localhost_origin_only_under_developer_mode(self):
		frappe.local.conf["developer_mode"] = 0
		doc = self._settings(
			login_with_passkey=1, passkey_rp_id="localhost", passkey_origins="http://localhost:8000"
		)
		self.assertRaises(frappe.ValidationError, doc.save)

		frappe.local.conf["developer_mode"] = 1
		doc = self._settings(
			login_with_passkey=1, passkey_rp_id="localhost", passkey_origins="http://localhost:8000"
		)
		doc.save()

	def test_localhost_origin_must_still_match_rp_scope(self):
		frappe.local.conf["developer_mode"] = 1
		doc = self._settings(
			login_with_passkey=1, passkey_rp_id="example.com", passkey_origins="http://localhost:8000"
		)
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_enable_requires_site_encryption_key(self):
		frappe.local.conf["encryption_key"] = None
		doc = self._settings(
			login_with_passkey=1,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		self.assertRaisesRegex(frappe.ValidationError, "encryption_key", doc.save)

	def test_origin_outside_rp_scope_is_refused(self):
		doc = self._settings(
			login_with_passkey=1, passkey_rp_id="example.com", passkey_origins="https://evil.test"
		)
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_subdomain_origin_with_port_is_allowed(self):
		doc = self._settings(
			login_with_passkey=1,
			passkey_rp_id="example.com",
			passkey_origins="https://sub.example.com:8443",
		)
		doc.save()

	def test_second_factor_requires_core_two_factor_auth(self):
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 0)
		doc = self._settings(
			passkey_as_second_factor=1,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		self.assertRaises(frappe.ValidationError, doc.save)

		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
		doc = self._settings(
			passkey_as_second_factor=1,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		doc.save()

	def test_negative_reauth_window_is_rejected(self):
		doc = self._settings(
			login_with_passkey=0,
			passkey_as_second_factor=0,
			passkey_origins="",
			passkey_app_origins="",
			passkey_reauth_window=-1,
		)
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_second_factor_only_is_rejected_when_password_login_is_disabled(self):
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", 1)
		doc = self._settings(
			login_with_passkey=0,
			passkey_as_second_factor=1,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		self.assertRaises(frappe.ValidationError, doc.save)

	def test_disable_guard_protects_passkey_only_users(self):
		"""Generalized guard: a save leaving no passkey-capable
		mode while flagged users exist is refused; the message lists them."""
		self.enable_passkey_login_mode()
		user = self.make_user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)

		doc = self._settings(login_with_passkey=0, passkey_as_second_factor=0)
		with self.assertRaises(frappe.ValidationError) as ctx:
			doc.save()
		self.assertIn(user, str(ctx.exception))

		# keeping one passkey-capable mode on: the save proceeds
		doc = self._settings(
			login_with_passkey=1,
			passkey_as_second_factor=0,
			passkey_rp_id="example.com",
			passkey_origins="https://example.com",
		)
		doc.save()

		# clearing the flag unblocks the all-off save
		frappe.db.set_value("WebAuthn User Handle", {"user": user}, "passkey_only_login", 0)
		doc = self._settings(login_with_passkey=0, passkey_as_second_factor=0)
		doc.save()
