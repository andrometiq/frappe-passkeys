# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Passkey Settings form support: the ``get_resolved_rp_id`` read endpoint that
feeds the settings form its server-truth RP ID (A1 — the form used to display the
browser host, which never matches an RP ID resolved from ``host_name``)."""

import frappe

from passkeys.passkeys.doctype.passkey_settings.passkey_settings import get_resolved_rp_id
from passkeys.tests.compat import IntegrationTestCase


class ResolvedRpIdEndpointTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self._host_name = frappe.conf.get("host_name")
		self.addCleanup(self._restore)

	def _restore(self):
		frappe.db.set_single_value(
			"Passkey Settings", "passkey_rp_id", self._snapshot.get("passkey_rp_id") or ""
		)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
		frappe.conf.host_name = self._host_name

	def _set_rp_id(self, value):
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", value)
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def test_explicit_field_wins_over_host_name(self):
		self._set_rp_id("example.com")
		frappe.conf.host_name = "https://ignored.example.net"
		self.assertEqual(get_resolved_rp_id()["rp_id"], "example.com")

	def test_falls_back_to_host_name_when_field_blank(self):
		self._set_rp_id("")
		frappe.conf.host_name = "https://site.example.org"
		out = get_resolved_rp_id()
		self.assertEqual(out["rp_id"], "site.example.org")
		self.assertTrue(out["host_name_configured"])

	def test_none_when_nothing_resolves(self):
		self._set_rp_id("")
		frappe.conf.host_name = None
		out = get_resolved_rp_id()
		self.assertIsNone(out["rp_id"])
		self.assertFalse(out["host_name_configured"])
