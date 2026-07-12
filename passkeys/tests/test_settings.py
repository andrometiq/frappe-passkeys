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


class EnrollmentPolicyValidatorTest(IntegrationTestCase):
	"""The adoption-ladder validator guards on the Passkey Settings Single. Modes stay
	OFF throughout so ``_validate_enablement`` (RP-ID resolution) never interferes —
	the enforcement guards are orthogonal to enablement."""

	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.addCleanup(self._restore)

	def _restore(self):
		doc = frappe.get_doc("Passkey Settings")
		for field in (
			"passkey_enrollment_policy",
			"passkey_enforce_after",
			"passkey_enforce_scope",
			"passkey_enforce_grace_logins",
			"passkey_enforce_incapable",
		):
			doc.set(field, self._snapshot.get(field))
		doc.flags.ignore_permissions = True
		doc.flags.ignore_mandatory = True
		doc.save()
		frappe.clear_document_cache("Passkey Settings", "Passkey Settings")

	def _save(self, **values):
		doc = frappe.get_doc("Passkey Settings")
		doc.login_with_passkey = 0
		doc.passkey_as_second_factor = 0
		for field, value in values.items():
			doc.set(field, value)
		doc.flags.ignore_permissions = True
		doc.save()
		return doc

	def test_enforce_after_date_requires_a_date(self):
		with self.assertRaises(frappe.ValidationError):
			self._save(passkey_enrollment_policy="Enforce After Date", passkey_enforce_after=None)
		# with a date it saves
		self._save(passkey_enrollment_policy="Enforce After Date", passkey_enforce_after="2027-01-01")

	def test_negative_grace_logins_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			self._save(passkey_enrollment_policy="Enforce", passkey_enforce_grace_logins=-1)

	def test_enforce_saves_with_warnings_but_not_blocked(self):
		# All Users + System Manager not exempt only WARNS (msgprint) — the save proceeds.
		doc = self._save(
			passkey_enrollment_policy="Enforce",
			passkey_enforce_scope="All Users",
			passkey_enforce_grace_logins=0,
		)
		self.assertEqual(doc.passkey_enrollment_policy, "Enforce")
