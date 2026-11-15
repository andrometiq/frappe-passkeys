# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Well-known documents (``passkeys.well_known``): the settings-driven
``assetlinks.json`` (Android), ``apple-app-site-association`` (iOS) and
``passkey-endpoints`` (W3C) generators and their guest endpoints. The endpoints must
emit a BARE JSON document with an explicit ``application/json`` content type and 404
when unconfigured."""

import json
from unittest.mock import patch

import frappe
from frappe.utils import cint, set_request

from passkeys import well_known
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache

PACKAGE = "com.example.app"
FINGERPRINT = (
	"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
)
TEAM_ID = "ABCDE12345"
BUNDLE_ID = "com.example.app"


class TestFingerprintNormalization(IntegrationTestCase):
	def test_colonless_paste_is_grouped(self):
		raw = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
		self.assertEqual(well_known._fingerprints(raw), [FINGERPRINT])

	def test_lowercase_and_colons_normalize(self):
		self.assertEqual(well_known._fingerprints(FINGERPRINT.lower()), [FINGERPRINT])

	def test_space_separated_hex_is_normalized(self):
		# spaces/tabs between byte pairs must parse, not silently drop to a 404
		self.assertEqual(well_known._fingerprints(FINGERPRINT.replace(":", " ")), [FINGERPRINT])

	def test_keytool_sha256_label_is_stripped(self):
		# a copied `keytool -list` line — the leading label must not corrupt the hex.
		self.assertEqual(well_known._fingerprints(f"  SHA256: {FINGERPRINT}"), [FINGERPRINT])
		self.assertEqual(well_known._fingerprints(f"SHA-256 = {FINGERPRINT.lower()}"), [FINGERPRINT])

	def test_blank_and_hexless_lines_dropped_and_deduped(self):
		raw = f"\n{FINGERPRINT}\n   \n{FINGERPRINT.lower()}\n"
		self.assertEqual(well_known._fingerprints(raw), [FINGERPRINT])

	def test_truncated_or_malformed_fingerprints_are_rejected(self):
		self.assertEqual(well_known._fingerprints("AB:CD:EF:01"), [])
		self.assertEqual(well_known._fingerprints(FINGERPRINT.replace("AB", "ZZ", 1)), [])

	def test_empty_input(self):
		self.assertEqual(well_known._fingerprints(""), [])
		self.assertEqual(well_known._fingerprints(None), [])


class TestBuilders(IntegrationTestCase):
	def test_assetlinks_shape(self):
		settings = frappe._dict(
			{"passkey_android_package_name": PACKAGE, "passkey_android_cert_fingerprints": FINGERPRINT}
		)
		out = well_known.build_assetlinks(settings)
		self.assertEqual(len(out), 1)
		self.assertEqual(out[0]["target"]["namespace"], "android_app")
		self.assertEqual(out[0]["target"]["package_name"], PACKAGE)
		self.assertEqual(out[0]["target"]["sha256_cert_fingerprints"], [FINGERPRINT])
		# get_login_creds is the relation that enables credential sharing.
		self.assertIn("delegate_permission/common.get_login_creds", out[0]["relation"])

	def test_assetlinks_none_when_package_or_fingerprints_missing(self):
		self.assertIsNone(
			well_known.build_assetlinks(frappe._dict({"passkey_android_cert_fingerprints": FINGERPRINT}))
		)
		self.assertIsNone(
			well_known.build_assetlinks(frappe._dict({"passkey_android_package_name": PACKAGE}))
		)
		self.assertIsNone(well_known.build_assetlinks(frappe._dict({})))

	def test_aasa_shape(self):
		settings = frappe._dict({"passkey_ios_team_id": TEAM_ID, "passkey_ios_bundle_id": BUNDLE_ID})
		self.assertEqual(
			well_known.build_apple_app_site_association(settings),
			{"webcredentials": {"apps": [f"{TEAM_ID}.{BUNDLE_ID}"]}},
		)

	def test_aasa_none_when_team_or_bundle_missing(self):
		self.assertIsNone(
			well_known.build_apple_app_site_association(frappe._dict({"passkey_ios_team_id": TEAM_ID}))
		)
		self.assertIsNone(
			well_known.build_apple_app_site_association(frappe._dict({"passkey_ios_bundle_id": BUNDLE_ID}))
		)
		self.assertIsNone(well_known.build_apple_app_site_association(frappe._dict({})))

	def test_passkey_endpoints_need_a_login_mode(self):
		settings = frappe._dict(passkey_rp_id="example.com", passkey_origins="https://example.com")
		with patch.dict(frappe.conf, {"host_name": ""}):
			self.assertIsNone(well_known.build_passkey_endpoints(settings))
			for mode in ("login_with_passkey", "passkey_as_second_factor"):
				with self.subTest(mode=mode):
					self.assertEqual(
						well_known.build_passkey_endpoints(frappe._dict(settings, **{mode: 1})),
						{"enroll": "https://example.com/passkeys", "manage": "https://example.com/passkeys"},
					)

	def test_passkey_endpoints_prefer_host_name_then_the_first_https_origin(self):
		settings = frappe._dict(
			login_with_passkey=1,
			passkey_rp_id="example.com",
			passkey_origins="https://login.example.com\nhttps://example.com",
		)
		for host_name, expected in (
			("https://erp.example.com", "https://erp.example.com/passkeys"),
			("https://outside.test", "https://login.example.com/passkeys"),
			("http://erp.example.com", "https://login.example.com/passkeys"),
			("", "https://login.example.com/passkeys"),
		):
			with self.subTest(host_name=host_name), patch.dict(frappe.conf, {"host_name": host_name}):
				self.assertEqual(well_known.build_passkey_endpoints(settings)["manage"], expected)

	def test_passkey_endpoints_need_an_https_origin(self):
		settings = frappe._dict(
			login_with_passkey=1, passkey_rp_id="localhost", passkey_origins="http://localhost:8000"
		)
		with patch.dict(frappe.conf, {"host_name": "", "developer_mode": 1}):
			self.assertIsNone(well_known.build_passkey_endpoints(settings))


class TestEndpoints(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(self._restore)
		# Pin a valid relying party so _save() validates only the mobile fields, whatever
		# login state an earlier test left behind (a blank RP ID resolves from host_name).
		self._set(passkey_rp_id="example.com", passkey_origins="https://example.com")

	def _restore(self):
		for field in (
			"passkey_rp_id",
			"passkey_origins",
			"passkey_android_package_name",
			"passkey_android_cert_fingerprints",
			"passkey_ios_team_id",
			"passkey_ios_bundle_id",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or "")
		for field in ("login_with_passkey", "passkey_as_second_factor"):
			frappe.db.set_single_value("Passkey Settings", field, cint(self._snapshot.get(field)))
		flush_settings_cache()

	def _set(self, **values):
		for field, value in values.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		flush_settings_cache()

	def _assert_json_response(self, response, expected):
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.headers["Content-Type"], "application/json")
		self.assertEqual(json.loads(response.get_data(as_text=True)), expected)
		self.assertEqual(response.headers["Cache-Control"], "public, max-age=3600")
		self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

	def test_assetlinks_endpoint_serves_bare_json(self):
		self._set(passkey_android_package_name=PACKAGE, passkey_android_cert_fingerprints=FINGERPRINT)
		response = well_known.assetlinks()
		body = json.loads(response.get_data(as_text=True))
		# a bare list — NOT wrapped in {"message": ...}
		self.assertIsInstance(body, list)
		self.assertEqual(body[0]["target"]["package_name"], PACKAGE)
		self.assertEqual(response.headers["Content-Type"], "application/json")
		self.assertEqual(response.headers["Cache-Control"], "public, max-age=3600")

	def test_assetlinks_endpoint_404_when_unconfigured(self):
		self._set(passkey_android_package_name="", passkey_android_cert_fingerprints="")
		with self.assertRaises(frappe.DoesNotExistError):
			well_known.assetlinks()

	def test_aasa_endpoint_serves_bare_json(self):
		self._set(passkey_ios_team_id=TEAM_ID, passkey_ios_bundle_id=BUNDLE_ID)
		self._assert_json_response(
			well_known.apple_app_site_association(),
			{"webcredentials": {"apps": [f"{TEAM_ID}.{BUNDLE_ID}"]}},
		)

	def test_aasa_endpoint_404_when_unconfigured(self):
		self._set(passkey_ios_team_id="", passkey_ios_bundle_id="")
		with self.assertRaises(frappe.DoesNotExistError):
			well_known.apple_app_site_association()

	def _guest_get(self, path="/api/method/passkeys.well_known.passkey_endpoints", headers=None):
		for attribute in ("request", "request_ip", "form_dict"):
			self.addCleanup(setattr, frappe.local, attribute, getattr(frappe.local, attribute, None))
		set_request(method="GET", path=path, headers=headers)
		frappe.local.request_ip = frappe.generate_hash(length=12)
		frappe.local.form_dict = frappe._dict(cmd="passkeys.well_known.passkey_endpoints")
		frappe.set_user("Guest")
		self.addCleanup(frappe.set_user, "Administrator")

	def test_passkey_endpoints_endpoint_serves_bare_json(self):
		self._set(login_with_passkey=1, passkey_as_second_factor=0)
		self._guest_get()
		with patch.dict(frappe.conf, {"host_name": "https://outside.test"}):
			response = well_known.passkey_endpoints()
		self._assert_json_response(
			response, {"enroll": "https://example.com/passkeys", "manage": "https://example.com/passkeys"}
		)

	def test_passkey_endpoints_endpoint_404_with_both_login_modes_off(self):
		self._set(login_with_passkey=0, passkey_as_second_factor=0)
		self._guest_get()
		with self.assertRaises(frappe.DoesNotExistError):
			well_known.passkey_endpoints()

	def test_passkey_endpoints_never_read_request_host_headers(self):
		self._set(login_with_passkey=1)
		self._guest_get(
			headers=[
				("Host", "evil.example.net"),
				("X-Forwarded-Host", "evil.example.net"),
				("X-Forwarded-Proto", "http"),
			]
		)
		with patch.dict(frappe.conf, {"host_name": "https://outside.test"}):
			body = json.loads(well_known.passkey_endpoints().get_data(as_text=True))
		self.assertEqual(body["enroll"], "https://example.com/passkeys")
		self.assertEqual(body["manage"], "https://example.com/passkeys")

	def test_passkey_endpoints_endpoint_is_rate_limited_per_ip(self):
		self._set(login_with_passkey=1)
		self._guest_get()
		for _ in range(120):
			well_known.passkey_endpoints()
		with self.assertRaises(frappe.RateLimitExceededError):
			well_known.passkey_endpoints()
		frappe.local.request_ip = frappe.generate_hash(length=12)
		self.assertEqual(well_known.passkey_endpoints().status_code, 200)

	def _save(self, **values):
		settings = frappe.get_doc("Passkey Settings")
		settings.update(values)
		settings.save(ignore_permissions=True)
		flush_settings_cache()

	def test_malformed_values_are_refused_on_save(self):
		self._set(
			passkey_android_package_name="",
			passkey_android_cert_fingerprints="",
			passkey_ios_team_id="",
			passkey_ios_bundle_id="",
		)
		cases = (
			{"passkey_android_cert_fingerprints": f"{FINGERPRINT}\nAB:CD:EF:01"},
			{"passkey_ios_team_id": "abcde12345"},
			{"passkey_ios_team_id": "ABCDE1234"},
			{"passkey_ios_bundle_id": "example"},
			{"passkey_ios_bundle_id": "com.example app"},
		)
		for values in cases:
			with self.subTest(values=values), self.assertRaises(frappe.ValidationError):
				self._save(**values)
			self.assertFalse(frappe.db.get_single_value("Passkey Settings", next(iter(values))))

	def test_valid_values_save_and_are_served(self):
		self._save(
			passkey_android_package_name=PACKAGE,
			passkey_android_cert_fingerprints=f"{FINGERPRINT.replace(':', '').lower()}\n",
			passkey_ios_team_id=TEAM_ID,
			passkey_ios_bundle_id=BUNDLE_ID,
		)
		self._assert_json_response(
			well_known.apple_app_site_association(), {"webcredentials": {"apps": [f"{TEAM_ID}.{BUNDLE_ID}"]}}
		)
		self.assertEqual(
			json.loads(well_known.assetlinks().get_data(as_text=True))[0]["target"][
				"sha256_cert_fingerprints"
			],
			[FINGERPRINT],
		)
