# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin security-posture verdict. ``classify_posture`` is pure (no DB / request), so
the permutation coverage runs on plain input dicts; one smoke test exercises the real
``build_posture`` reads + the whitelisted endpoint shape."""

import frappe

from passkeys import posture
from passkeys.tests.compat import IntegrationTestCase

# A fully-locked-down baseline: passwordless first factor on, no other stock login
# method, hardening on. Tests override just the fields they exercise.
_LOCKED = {
	"first_factor": True,
	"second_factor": False,
	"password_login_enabled": False,
	"email_link_login": False,
	"social_providers": [],
	"ldap_enabled": False,
	"core_2fa_enabled": False,
	"core_2fa_method": None,
	"passkey_only_user_count": 5,
	"login_user_count": 5,
	"enforcement_effective": "enforce",
	"sign_count_hard_fail": True,
	"reauth_window": 600,
}


def _ctx(**overrides):
	ctx = dict(_LOCKED)
	ctx.update(overrides)
	return ctx


def _codes(result):
	return [row["code"] for row in result["rows"]]


class ClassifyPostureTest(IntegrationTestCase):
	def test_locked_down_site_has_no_bypass(self):
		result = posture.classify_posture(_ctx())
		self.assertFalse(result["verdict"]["can_bypass"])
		self.assertEqual(result["verdict"]["bypass_labels"], [])
		self.assertEqual(result["verdict"]["tone"], "good")
		# only the honest-limit disclaimer survives, and it is not deterministically detectable
		self.assertIn("custom_apps", _codes(result))
		disclaimer = next(r for r in result["rows"] if r["code"] == "custom_apps")
		self.assertFalse(disclaimer["detectable"])

	def test_no_mode_reports_not_active(self):
		result = posture.classify_posture(_ctx(first_factor=False, second_factor=False))
		self.assertFalse(result["verdict"]["can_bypass"])
		self.assertEqual(_codes(result), ["no_mode", "custom_apps"])

	def test_password_login_is_a_first_factor_bypass(self):
		result = posture.classify_posture(_ctx(password_login_enabled=True))
		self.assertTrue(result["verdict"]["can_bypass"])
		self.assertIn("password sign-in", result["verdict"]["bypass_labels"])
		row = next(r for r in result["rows"] if r["code"] == "password_login")
		self.assertEqual(row["severity"], "high")
		self.assertTrue(row["detectable"])
		# password reset + adoption ride along once password sign-in is a bypass
		self.assertIn("password_reset", _codes(result))
		self.assertIn("adoption", _codes(result))

	def test_password_login_not_a_bypass_in_second_factor_only_mode(self):
		# second-factor-only: password rides the passkey step, so it is NOT a bypass; the
		# floor row (core 2FA) carries the risk instead.
		result = posture.classify_posture(
			_ctx(first_factor=False, second_factor=True, password_login_enabled=True, core_2fa_enabled=True)
		)
		self.assertNotIn("password_login", _codes(result))
		self.assertNotIn("password_reset", _codes(result))
		self.assertIn("core_2fa_on", _codes(result))
		self.assertFalse(result["verdict"]["can_bypass"])

	def test_second_factor_floor_off_is_unsupported_but_final_vetoed(self):
		result = posture.classify_posture(
			_ctx(first_factor=False, second_factor=True, core_2fa_enabled=False)
		)
		self.assertFalse(result["verdict"]["can_bypass"])
		row = next(r for r in result["rows"] if r["code"] == "core_2fa_off")
		self.assertEqual(row["severity"], "high")
		self.assertIsNone(row["bypass_label"])

	def test_social_and_ldap_and_email_link_are_bypasses(self):
		result = posture.classify_posture(
			_ctx(social_providers=["Google", "GitHub"], ldap_enabled=True, email_link_login=True)
		)
		labels = result["verdict"]["bypass_labels"]
		self.assertIn("social login", labels)
		self.assertIn("LDAP sign-in", labels)
		self.assertIn("email-link sign-in", labels)
		social = next(r for r in result["rows"] if r["code"] == "social_login")
		self.assertIn("Google", social["what"])
		self.assertIn("GitHub", social["what"])
		# email-link is a softer bypass than social/ldap
		email = next(r for r in result["rows"] if r["code"] == "email_link")
		self.assertEqual(email["severity"], "medium")

	def test_alternate_logins_are_availability_risks_not_bypasses_under_second_factor(self):
		result = posture.classify_posture(
			_ctx(
				first_factor=False,
				second_factor=True,
				core_2fa_enabled=True,
				social_providers=["Google"],
				ldap_enabled=True,
				email_link_login=True,
			)
		)
		self.assertFalse(result["verdict"]["can_bypass"])
		for code in ("social_login", "ldap", "email_link"):
			row = next(r for r in result["rows"] if r["code"] == code)
			self.assertIsNone(row["bypass_label"])
			self.assertIn("cannot finish", row["why"])

	def test_bypass_labels_are_severity_ordered(self):
		# password(high) + email-link(medium) → high label precedes the medium label.
		result = posture.classify_posture(_ctx(password_login_enabled=True, email_link_login=True))
		labels = result["verdict"]["bypass_labels"]
		self.assertLess(labels.index("password sign-in"), labels.index("email-link sign-in"))

	def test_hardening_rows_only_when_weak(self):
		soft = posture.classify_posture(_ctx(sign_count_hard_fail=False, reauth_window=3600))
		self.assertIn("sign_count_soft", _codes(soft))
		self.assertIn("reauth_window", _codes(soft))
		# defaults (hard-fail on, short window) → neither row
		strong = posture.classify_posture(_ctx(sign_count_hard_fail=True, reauth_window=600))
		self.assertNotIn("sign_count_soft", _codes(strong))
		self.assertNotIn("reauth_window", _codes(strong))

	def test_every_row_carries_the_full_contract(self):
		result = posture.classify_posture(
			_ctx(password_login_enabled=True, email_link_login=True, sign_count_hard_fail=False)
		)
		for row in result["rows"]:
			for key in ("code", "severity", "what", "why", "recommendation", "detectable"):
				self.assertIn(key, row)
			self.assertIn(row["severity"], posture.SEVERITY_RANK)
			self.assertTrue(row["what"] and row["recommendation"])


class BuildPostureSmokeTest(IntegrationTestCase):
	"""Exercises the real reads + the whitelisted endpoint shape against the current
	site — asserts structure, not a specific verdict (site config varies)."""

	def test_build_posture_returns_the_contract(self):
		result = posture.build_posture()
		self.assertIn("verdict", result)
		self.assertIn("rows", result)
		self.assertIsInstance(result["rows"], list)
		self.assertIn("can_bypass", result["verdict"])
		# the honest-limit disclaimer is always present
		self.assertTrue(any(r["code"] == "custom_apps" for r in result["rows"]))

	def test_endpoint_is_system_manager_gated(self):
		from passkeys.passkeys.doctype.passkey_settings.passkey_settings import get_security_posture

		# Administrator holds System Manager in the test runner — the endpoint returns.
		result = get_security_posture()
		self.assertIn("verdict", result)

		frappe.set_user("Guest")
		# v15's frappe.only_for is a no-op while flags.in_test is set (v16+ dropped
		# that short-circuit); clear it so the real System Manager gate is exercised.
		saved_in_test = getattr(frappe.flags, "in_test", False)
		frappe.flags.in_test = False
		try:
			with self.assertRaises(frappe.PermissionError):
				get_security_posture()
		finally:
			frappe.flags.in_test = saved_in_test
			frappe.set_user("Administrator")


class AdoptionCountsTest(IntegrationTestCase):
	"""The adoption numerator (passkey_only handles) is counted over the SAME enabled,
	non-Administrator/Guest population as the denominator, so it can never exceed it
	(n <= m). It used to count handles over ALL users, so an Administrator or disabled
	user with a passkey-only handle could push n above m."""

	def _make_user(self, enabled=1) -> str:
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": f"posture-{frappe.generate_hash(length=8)}@example.com",
				"first_name": "Posture",
				"enabled": enabled,
				"send_welcome_email": 0,
			}
		)
		user.flags.no_welcome_mail = True
		user.insert(ignore_permissions=True)
		self.addCleanup(frappe.delete_doc, "User", user.name, force=1, ignore_permissions=True)
		return user.name

	def _passkey_only_handle(self, user: str) -> None:
		handle = frappe.get_doc(
			{"doctype": "WebAuthn User Handle", "user": user, "handle": frappe.generate_hash(length=64)}
		).insert(ignore_permissions=True)
		# flip the flag directly — the enabled-credential floor is irrelevant to counting
		frappe.db.set_value("WebAuthn User Handle", handle.name, "passkey_only_login", 1)
		self.addCleanup(
			frappe.delete_doc, "WebAuthn User Handle", handle.name, force=1, ignore_permissions=True
		)

	def test_numerator_never_exceeds_the_denominator(self):
		n0, m0 = posture._adoption_counts()
		self.assertLessEqual(n0, m0)

		# an enabled, eligible user with a passkey-only handle lifts BOTH counts by one
		self._passkey_only_handle(self._make_user(enabled=1))
		n1, m1 = posture._adoption_counts()
		self.assertEqual((n1, m1), (n0 + 1, m0 + 1))

		# a DISABLED user with a passkey-only handle lifts NEITHER (excluded from n and m)
		self._passkey_only_handle(self._make_user(enabled=0))
		n2, m2 = posture._adoption_counts()
		self.assertEqual((n2, m2), (n1, m1))
		self.assertLessEqual(n2, m2)

	def test_administrator_passkey_only_handle_is_excluded_from_numerator(self):
		if frappe.db.exists("WebAuthn User Handle", {"user": "Administrator"}):
			self.skipTest("Administrator already has a WebAuthn User Handle on this site")
		n0, m0 = posture._adoption_counts()
		self._passkey_only_handle("Administrator")
		# Administrator is out of both populations, so neither count moves
		self.assertEqual(posture._adoption_counts(), (n0, m0))
