# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Mobile-app association files (``passkeys.well_known``): the settings-driven
``assetlinks.json`` (Android) and ``apple-app-site-association`` (iOS) generators and
their guest endpoints. The endpoints must emit a BARE JSON document with an explicit
``application/json`` content type and 404 when unconfigured."""

import json

import frappe

from passkeys import well_known
from passkeys.tests.compat import IntegrationTestCase

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
		self.assertEqual(well_known._fingerprints("ab:cd:ef:01"), ["AB:CD:EF:01"])

	def test_keytool_sha256_label_is_stripped(self):
		# a copied `keytool -list` line — the leading label must not corrupt the hex.
		self.assertEqual(well_known._fingerprints("  SHA256: AB:CD:EF:01"), ["AB:CD:EF:01"])
		self.assertEqual(well_known._fingerprints("SHA-256 = ab:cd"), ["AB:CD"])

	def test_blank_and_hexless_lines_dropped_and_deduped(self):
		raw = "\nAB:CD\n   \nab:cd\n"
		self.assertEqual(well_known._fingerprints(raw), ["AB:CD"])

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


class TestEndpoints(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(self._restore)

	def _restore(self):
		for field in (
			"passkey_android_package_name",
			"passkey_android_cert_fingerprints",
			"passkey_ios_team_id",
			"passkey_ios_bundle_id",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field) or "")
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _set(self, **values):
		for field, value in values.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _assert_json_response(self, response, expected):
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.headers["Content-Type"], "application/json")
		self.assertEqual(json.loads(response.get_data(as_text=True)), expected)

	def test_assetlinks_endpoint_serves_bare_json(self):
		self._set(passkey_android_package_name=PACKAGE, passkey_android_cert_fingerprints=FINGERPRINT)
		response = well_known.assetlinks()
		body = json.loads(response.get_data(as_text=True))
		# a bare list — NOT wrapped in {"message": ...}
		self.assertIsInstance(body, list)
		self.assertEqual(body[0]["target"]["package_name"], PACKAGE)
		self.assertEqual(response.headers["Content-Type"], "application/json")

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
