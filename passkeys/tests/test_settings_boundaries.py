# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""J1 — exhaustive settings/boundary unit tests.

Closes the boundary gaps the tests-&-CI map named as unpinned:

* ``passkey_max_per_user`` — the cap **enforcement** (never exercised before; only
  the default value was asserted): ``cap-1`` allowed / ``cap`` and ``cap+1``
  refused, the degenerate ``cap=1``, and the ``0``/blank → default-10 coercion,
  both as a direct unit sweep of ``_enforce_max_per_user`` AND end-to-end through
  the real ``begin_registration`` call site.
* ``passkey_reauth_window`` — the sudo-window TTL honoured at **non-default**
  values (only the default 600 was covered), the ``0``→600 coercion, and the
  exactly-expiry boundary.
* Exact tipping points the representative-value tests skip: the nudge cooldown at
  *exactly* N days (both sides of the ``<`` compare), the nudge cap at
  ``declines == cap`` vs ``cap-1``, the enforcement grace budget at ``grace=1`` and
  the ``max(0, …)`` clamp, and ``Enforce After Date`` when the date **is today**
  (the ``<=`` boundary).

Scoped to real coupling per the map — no blind Cartesian. Uses the established
``set_single_value`` + ``clear_document_cache`` idiom.
"""

import time

import frappe
from frappe.utils import add_to_date, now_datetime, nowdate

from passkeys import boot, session, state
from passkeys.api import registration
from passkeys.passkeys.doctype.passkey_settings.passkey_settings import get_resolved_rp_id
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_user
from passkeys.tests.soft_authenticator import SoftAuthenticator

RP_ID = "example.com"
ORIGIN = "https://example.com"


# ===========================================================================
# passkey_max_per_user — cap enforcement (the biggest named gap)
# ===========================================================================


class MaxPerUserCapUnitTest(IntegrationTestCase):
	"""Direct boundary sweep of ``registration._enforce_max_per_user`` — the pure
	cap predicate (``len(credentials) >= int(settings.passkey_max_per_user or 10)``).
	No ceremony setup needed: it takes a settings-like object + a credential list."""

	def _settings(self, cap):
		return frappe._dict({"passkey_max_per_user": cap})

	def _creds(self, n):
		return [frappe._dict({"credential_id": f"cred-{i}"}) for i in range(n)]

	def _enforce(self, cap, n):
		registration._enforce_max_per_user(self._settings(cap), self._creds(n), "explicit")

	def test_below_cap_allowed(self):
		self._enforce(cap=3, n=2)  # cap-1 — no raise

	def test_at_cap_refused(self):
		with self.assertRaises(frappe.ValidationError):
			self._enforce(cap=3, n=3)  # == cap (the >= boundary)

	def test_above_cap_refused(self):
		with self.assertRaises(frappe.ValidationError):
			self._enforce(cap=3, n=4)  # cap+1

	def test_cap_of_one_allows_zero_refuses_one(self):
		self._enforce(cap=1, n=0)  # first enrollment allowed
		with self.assertRaises(frappe.ValidationError):
			self._enforce(cap=1, n=1)  # a second is refused

	def test_zero_coerces_to_default_ten(self):
		# int(settings.passkey_max_per_user or 10): a stored 0 silently becomes 10.
		self._enforce(cap=0, n=9)  # 9 < 10 — allowed
		with self.assertRaises(frappe.ValidationError):
			self._enforce(cap=0, n=10)  # == 10 — refused

	def test_blank_and_none_coerce_to_default_ten(self):
		self._enforce(cap="", n=9)
		self._enforce(cap=None, n=9)
		with self.assertRaises(frappe.ValidationError):
			self._enforce(cap=None, n=10)

	def test_error_message_names_the_cap(self):
		with self.assertRaises(frappe.ValidationError) as ctx:
			self._enforce(cap=2, n=2)
		self.assertIn("maximum of 2", str(ctx.exception))


class MaxPerUserCapIntegrationTest(IntegrationTestCase):
	"""End-to-end proof the cap fires at the real call site — ``begin_registration``
	counts the user's stored ``WebAuthn Credential`` rows and throws at the cap."""

	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		# Faithful restore (never `or 0` — that writes a literal "0" into the text rp/origin fields).
		for field in ("login_with_passkey", "passkey_rp_id", "passkey_origins", "passkey_max_per_user"):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field))
		flush_settings_cache()
		# begin_registration commits mid-test, defeating the runner's per-test rollback; commit the
		# restore (and the addCleanup user delete that ran just before it) so nothing leaks onward.
		frappe.db.commit()

	def _set_cap(self, cap):
		frappe.db.set_single_value("Passkey Settings", "passkey_max_per_user", cap)
		flush_settings_cache()

	def _user(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def test_begin_registration_allows_below_cap_refuses_at_cap(self):
		self._set_cap(2)
		user = self._user()
		frappe.set_user(user)
		state.set_sudo_window(frappe.session.sid, {"user": user, "seeded_by": "password"}, ttl=600)

		# one existing credential (cap-1) — the ceremony still begins
		make_credential(user)
		begun = registration.begin_registration(flow="explicit")
		self.assertIn("state_id", begun)

		# a second existing credential brings the count to the cap — refused
		make_credential(user)
		with self.assertRaises(frappe.ValidationError) as ctx:
			registration.begin_registration(flow="explicit")
		self.assertIn("maximum of 2", str(ctx.exception))


# ===========================================================================
# passkey_reauth_window — sudo-window TTL at non-default values
# ===========================================================================


class ReauthWindowTtlTest(IntegrationTestCase):
	"""``session.seed_sudo_window`` reads ``cint(settings.passkey_reauth_window) or
	600`` and hands it to Redis ``ex`` as the sole expiry authority. The prior
	battery only ever proved the default 600; here the custom value is the actual
	seeded TTL, the 0→600 coercion holds, and a short window truly expires."""

	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_single_value("Passkey Settings", "passkey_reauth_window")
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		frappe.db.set_single_value("Passkey Settings", "passkey_reauth_window", self._snapshot or 600)
		flush_settings_cache()
		frappe.local.flags.pop("passkey_login", None)
		# seed_sudo_window's login flow commits mid-test; commit the restore so a custom/0 window
		# (test_zero_window sets 0) never leaks onto the shared single for a later module/run.
		frappe.db.commit()

	def _set_window(self, seconds):
		frappe.db.set_single_value("Passkey Settings", "passkey_reauth_window", seconds)
		flush_settings_cache()

	def _user(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _seed(self, user):
		frappe.set_user(user)
		frappe.local.flags.passkey_login = 1
		session.seed_sudo_window()
		frappe.local.flags.pop("passkey_login", None)

	def _pttl_ms(self):
		return frappe.cache.pttl(state._make_key(state.SUDO_PREFIX + frappe.session.sid))

	def test_custom_small_window_is_the_seeded_ttl(self):
		self._set_window(30)
		self._seed(self._user())
		pttl = self._pttl_ms()
		# ~30 s, allowing a couple of seconds of test-execution slack under the ceiling
		self.assertGreater(pttl, 28_000)
		self.assertLessEqual(pttl, 30_000)

	def test_large_custom_window_is_the_seeded_ttl(self):
		self._set_window(7200)
		self._seed(self._user())
		pttl = self._pttl_ms()
		self.assertGreater(pttl, 7_198_000)
		self.assertLessEqual(pttl, 7_200_000)

	def test_zero_window_coerces_to_default_600(self):
		# a stored 0 must seed the 600 default, never a 0-TTL (instantly-expiring) window.
		self._set_window(0)
		self._seed(self._user())
		pttl = self._pttl_ms()
		self.assertGreater(pttl, 598_000)
		self.assertLessEqual(pttl, 600_000)

	def test_short_window_expires_at_the_boundary(self):
		# a 1 s window genuinely drops the sudo grant once the TTL elapses (exactly-expiry).
		self._set_window(1)
		user = self._user()
		self._seed(user)
		self.assertTrue(session.has_management_sudo(user))
		time.sleep(1.2)
		self.assertFalse(session.has_management_sudo(user))


# ===========================================================================
# nudge cooldown / cap — exact tipping points
# ===========================================================================


class NudgeBoundaryTest(IntegrationTestCase):
	"""The nudge cadence's exact edges at CUSTOM knob values (the existing battery
	only walks representative values at the defaults): the cooldown ``<`` compare
	and the ``declines >= cap`` compare."""

	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		# set_single_value (not `.save()`) is the established settings-test idiom, and it
		# deliberately bypasses `Passkey Settings.validate`: this test exercises the nudge
		# cadence, not the origin validator, so a leaked/foreign `passkey_origins` value
		# left on the shared single by an earlier committing test must not break its setup.
		for field, value in {
			"passkey_enrollment_policy": "Nudge",
			"passkey_nudge_max_prompts": 3,
			"passkey_nudge_cooldown_days": 30,
		}.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		# Faithful restore (never `or 0` — that coerces a blank Select/int into a literal "0").
		for field in (
			"passkey_enrollment_policy",
			"passkey_nudge_max_prompts",
			"passkey_nudge_cooldown_days",
		):
			frappe.db.set_single_value("Passkey Settings", field, self._snapshot.get(field))
		flush_settings_cache()
		# set_default (nudge blob) commits mid-test; commit the restore + the addCleanup user/
		# DefaultValue deletes so nothing leaks into a later module or a later run.
		frappe.db.commit()

	def _set(self, **scalars):
		for field, value in scalars.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		flush_settings_cache()

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _user(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete,
			"DefaultValue",
			{"parent": boot.DEFAULTS_PARENT, "defkey": f"{user}_passkey_nudge"},
		)
		return user

	def _seed_nudge(self, user, declines=0, last_shown=None, opt_out=0):
		blob = {"declines": declines, "last_shown": last_shown, "opt_out": opt_out}
		frappe.db.set_default(f"{user}_passkey_nudge", frappe.as_json(blob), parent=boot.DEFAULTS_PARENT)

	def test_cooldown_boundary_at_exactly_n_days(self):
		# _cadence_ok gates on `elapsed < cooldown_days*86400`: at/just past the window
		# is eligible, just inside it is not — proven at a NON-default cooldown.
		cooldown = 7
		self._set(passkey_nudge_cooldown_days=cooldown)
		user = self._user()

		just_past = add_to_date(now_datetime(), days=-cooldown, seconds=-5).isoformat()
		self._seed_nudge(user, declines=1, last_shown=just_past)
		self.assertTrue(boot.nudge_eligible(user, self._settings(), 0))

		just_inside = add_to_date(now_datetime(), days=-cooldown, hours=1).isoformat()
		self._seed_nudge(user, declines=1, last_shown=just_inside)
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))

	def test_cap_boundary_declines_minus_one_vs_cap(self):
		# `declines >= cap` — cap-1 (cooldown clear) is eligible, exactly cap is not.
		cap = 5
		self._set(passkey_nudge_max_prompts=cap)
		user = self._user()

		self._seed_nudge(user, declines=cap - 1, last_shown=None)
		self.assertTrue(boot.nudge_eligible(user, self._settings(), 0))

		self._seed_nudge(user, declines=cap, last_shown=None)
		self.assertFalse(boot.nudge_eligible(user, self._settings(), 0))


# ===========================================================================
# enforcement grace budget / Enforce-After date — exact tipping points
# ===========================================================================


class EnforcementBoundaryTest(IntegrationTestCase):
	"""The enforcement verdict's exact edges the representative-value battery skips:
	a ``grace=1`` budget, the ``max(0, …)`` remaining clamp when over-spent, and
	``Enforce After Date`` when the date IS today (the ``<=`` server-clock compare)."""

	def setUp(self):
		super().setUp()
		self._snapshot = frappe.db.get_singles_dict("Passkey Settings")
		settings = frappe.get_doc("Passkey Settings")
		settings.passkey_rp_id = RP_ID
		settings.passkey_origins = ""
		settings.login_with_passkey = 1
		settings.passkey_as_second_factor = 0
		settings.passkey_enrollment_policy = "Enforce"
		settings.passkey_enforce_after = None
		settings.passkey_enforce_scope = "All Users"
		settings.passkey_enforce_grace_logins = 3
		settings.set("passkey_enforce_roles", [])
		settings.set("passkey_enforce_exempt_roles", [{"role": "System Manager"}])
		settings.save(ignore_permissions=True)
		flush_settings_cache()
		self.addCleanup(self._restore)
		self.addCleanup(frappe.set_user, "Administrator")

	def _restore(self):
		frappe.set_user("Administrator")
		doc = frappe.get_doc("Passkey Settings")
		for field in (
			"passkey_rp_id",
			"passkey_origins",
			"login_with_passkey",
			"passkey_as_second_factor",
			"passkey_enrollment_policy",
			"passkey_enforce_after",
			"passkey_enforce_scope",
			"passkey_enforce_grace_logins",
		):
			doc.set(field, self._snapshot.get(field))
		doc.set("passkey_enforce_roles", [])
		doc.set("passkey_enforce_exempt_roles", [{"role": "System Manager"}])
		doc.flags.ignore_permissions = True
		# Skip re-validation: this is a pure state restore, and a settings row left invalid by
		# an earlier committing test in the run must not make cleanup raise (cascade guard).
		doc.flags.ignore_validate = True
		doc.save()
		flush_settings_cache()
		# record_enforcement_event (set_default) commits mid-test; commit the restore + the
		# addCleanup user/DefaultValue deletes so no enforce state leaks onward.
		frappe.db.commit()

	def _set(self, **scalars):
		for field, value in scalars.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		flush_settings_cache()

	def _settings(self):
		return frappe.get_cached_doc("Passkey Settings")

	def _user(self):
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		self.addCleanup(
			frappe.db.delete,
			"DefaultValue",
			{"parent": boot.DEFAULTS_PARENT, "defkey": f"{user}_passkey_enforce"},
		)
		return user

	def _verdict(self, user, creds=0):
		return boot.build_enforcement(user, self._settings(), creds)

	def test_grace_one_blocks_on_first_deferral(self):
		self._set(passkey_enforce_grace_logins=1)
		user = self._user()
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 1)
		self.assertFalse(v["blocking"])
		self.assertEqual(v["reason"], "grace")

		boot.record_enforcement_event(user, "defer")
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 0)
		self.assertTrue(v["blocking"])

	def test_grace_remaining_never_negative_when_overspent(self):
		# grace_used (2) > grace_total (1) — max(0, total-used) clamps remaining to 0.
		self._set(passkey_enforce_grace_logins=1)
		user = self._user()
		boot.record_enforcement_event(user, "defer")
		boot.record_enforcement_event(user, "defer")
		v = self._verdict(user)
		self.assertEqual(v["grace_remaining"], 0)
		self.assertTrue(v["blocking"])

	def test_enforce_after_date_today_is_enforce(self):
		# getdate(after) <= getdate(nowdate()): today == today resolves to enforce (the
		# <= boundary the future/past tests straddle but never land on).
		self._set(passkey_enrollment_policy="Enforce After Date", passkey_enforce_after=nowdate())
		v = self._verdict(self._user())
		self.assertEqual(v["effective"], "enforce")
		self.assertTrue(v["in_scope"])


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
		flush_settings_cache()
		frappe.conf.host_name = self._host_name

	def _set_rp_id(self, value):
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", value)
		flush_settings_cache()

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
		flush_settings_cache()

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
