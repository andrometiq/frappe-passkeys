# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""AAGUID→provider display resolution: the vendored-
snapshot loader (known / unknown / zero / case-insensitive / ``_meta``-skipping)
and the default-label precedence at registration (provider name first,
attachment-derived neutral fallback otherwise)."""

import json
from types import SimpleNamespace

from passkeys import aaguid
from passkeys.api.registration import _default_label
from passkeys.tests.compat import IntegrationTestCase

# A stable curated entry (Google's software authenticator — in the community
# list since its first release; the node suite pins the same row).
KNOWN_AAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
KNOWN_NAME = "Google Password Manager"


class AaguidLookupTest(IntegrationTestCase):
	def test_known_aaguid_resolves_to_provider_name(self):
		self.assertEqual(aaguid.provider_name(KNOWN_AAGUID), KNOWN_NAME)

	def test_lookup_is_case_insensitive(self):
		# The column stores whatever the authenticator asserted; snapshot keys
		# are lowercase — an uppercase-stored AAGUID must still resolve.
		self.assertEqual(aaguid.provider_name(KNOWN_AAGUID.upper()), KNOWN_NAME)

	def test_unknown_zero_and_empty_aaguids_are_none(self):
		# Zero/unknown AAGUID ⇒ generic fallback, never an error.
		self.assertIsNone(aaguid.provider_name("11111111-2222-3333-4444-555555555555"))
		self.assertIsNone(aaguid.provider_name(aaguid.ZERO_AAGUID))
		self.assertIsNone(aaguid.provider_name(""))
		self.assertIsNone(aaguid.provider_name(None))

	def test_meta_key_is_provenance_not_a_lookup_row(self):
		# The vendored file carries a _meta attribution block (docs/aaguid-map.md);
		# the loader must skip underscore-prefixed keys so it can never resolve.
		self.assertIn("_meta", json.loads(aaguid._MAP_PATH.read_text()))
		self.assertIsNone(aaguid.provider_name("_meta"))
		self.assertNotIn("_meta", aaguid._load_map())

	def test_snapshot_is_present_and_lean(self):
		# Ships the map as a release asset: non-empty, and stripped of the
		# upstream icon blobs (every value is a plain name string).
		table = aaguid._load_map()
		self.assertGreater(len(table), 0)
		for key, value in table.items():
			self.assertEqual(key, key.lower())
			self.assertIsInstance(value, str)
			self.assertTrue(value.strip())


class DefaultLabelTest(IntegrationTestCase):
	def _result(self, aaguid_value="", attachment=None):
		return SimpleNamespace(aaguid=aaguid_value, authenticator_attachment=attachment)

	def test_provider_name_wins_over_attachment_default(self):
		# Precedence: a mapped AAGUID names the credential after its
		# provider, regardless of attachment.
		self.assertEqual(_default_label(self._result(KNOWN_AAGUID, "platform")), KNOWN_NAME)
		self.assertEqual(_default_label(self._result(KNOWN_AAGUID, "cross-platform")), KNOWN_NAME)

	def test_unknown_aaguid_falls_back_to_attachment_default(self):
		self.assertEqual(_default_label(self._result("", "platform")), "Device passkey")
		self.assertEqual(_default_label(self._result(aaguid.ZERO_AAGUID, "platform")), "Device passkey")
		self.assertEqual(
			_default_label(self._result("11111111-2222-3333-4444-555555555555", None)), "Passkey"
		)
