# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

import secrets
from unittest.mock import patch

import frappe
from frappe.utils import set_request

from passkeys import ceremony, request_security, state
from passkeys.tests.compat import IntegrationTestCase


class RequestSecurityTest(IntegrationTestCase):
	def test_identifier_preserves_non_email_case(self):
		for raw, expected in (
			(" Administrator ", "Administrator"),
			("MixedAlias", "MixedAlias"),
			(" A@EXAMPLE.COM ", "a@example.com"),
		):
			self.assertEqual(request_security.normalize_login_identifier(raw), expected)

	def test_ipv6_rotation_hits_shared_limit_without_changing_audit_ip(self):
		self.addCleanup(setattr, frappe.local, "request_ip", getattr(frappe.local, "request_ip", None))
		self.addCleanup(setattr, frappe.local, "form_dict", frappe.local.form_dict)
		set_request(method="POST", path="/api/method/passkeys.passkey.begin_login")
		frappe.local.form_dict = frappe._dict(cmd="passkeys.passkey.begin_login")
		prefix = "2001:db8:" + format(secrets.randbits(16) or 1, "x")
		key = f"{state.RATE_LIMIT_PREFIX}passkeys.passkey.begin_login:{prefix}:1::/64"
		self.addCleanup(state.clear_counter, key)
		self.addCleanup(state.clear_counter, key.replace(":1::/64", ":2::/64"))
		for suffix in [f"1::{index:x}" for index in range(1, 31)] + ["2::1"]:
			self.addCleanup(
				frappe.cache.delete,
				frappe.cache.make_key(f"rl:passkeys.passkey.begin_login:{prefix}:{suffix}"),
			)
		from passkeys import passkey

		with patch("frappe.get_cached_doc", return_value=frappe._dict(login_with_passkey=0)):
			for index in range(1, 31):
				frappe.local.request_ip = f"{prefix}:1::{index:x}"
				self.assertFalse(passkey.begin_login()["enabled"])
			frappe.local.request_ip = f"{prefix}:1::ffff"
			with self.assertRaises(frappe.RateLimitExceededError):
				passkey.begin_login()
			self.assertEqual(ceremony.request_ip(), f"{prefix}:1::ffff")
			frappe.local.request_ip = f"{prefix}:2::1"
			self.assertFalse(passkey.begin_login()["enabled"])
