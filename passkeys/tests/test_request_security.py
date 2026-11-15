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

	def test_guest_ceremony_endpoints_are_limited_per_ip(self):
		"""Each guest ceremony leg refuses the call past its limit, and only for that IP: an
		attacker exhausting their own bucket does not spend a victim's on another address."""
		from passkeys import passkey

		for attribute in ("request", "request_ip", "form_dict"):
			self.addCleanup(setattr, frappe.local, attribute, getattr(frappe.local, attribute, None))
		endpoints = (
			(passkey.verify_login, ("state", {}), 10),
			(passkey.complete_uv_setup, ("setup", "password"), 5),
			(passkey.login_with_password, ("someone@example.com", "password"), 10),
			(passkey.verify_second_factor, ("state", {}), 10),
			(passkey.fallback_to_otp, ("state",), 5),
		)
		modes_off = frappe._dict(login_with_passkey=0, passkey_as_second_factor=0)
		with patch("frappe.get_cached_doc", return_value=modes_off):
			for endpoint, arguments, limit in endpoints:
				with self.subTest(endpoint=endpoint.__name__):
					set_request(method="POST", path=f"/api/method/passkeys.passkey.{endpoint.__name__}")
					frappe.local.form_dict = frappe._dict(cmd=f"passkeys.passkey.{endpoint.__name__}")
					frappe.local.request_ip = frappe.generate_hash(length=12)
					for _ in range(limit):
						with self.assertRaises(frappe.AuthenticationError):
							endpoint(*arguments)
					with self.assertRaises(frappe.RateLimitExceededError):
						endpoint(*arguments)
					frappe.local.request_ip = frappe.generate_hash(length=12)
					with self.assertRaises(frappe.AuthenticationError):
						endpoint(*arguments)

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
