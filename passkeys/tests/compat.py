# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Test base-class shim: `IntegrationTestCase` on v16+/develop,
`FrappeTestCase` on v15 — without it the v15 CI leg fails at import."""

import frappe
from frappe.utils import cint

try:
	from frappe.tests import IntegrationTestCase
except ImportError:  # v15
	from frappe.tests.utils import FrappeTestCase as IntegrationTestCase

__all__ = [
	"IntegrationTestCase",
	"WebAuthnAssertMixin",
	"arrange_clean_login_policy",
	"arrange_mode_floor",
	"arrange_saveable_system_settings",
	"flush_settings_cache",
	"is_signed_out_by_frappe",
]


class WebAuthnAssertMixin:
	"""Shared soft-authenticator assertion builder for the request-cycle harnesses
	(login / second-factor / confirm), which all pin the same test RP."""

	def _assert(self, auth, options, **kw):
		return auth.assertion(
			challenge_b64=options["challenge"], rp_id="example.com", origin="https://example.com", **kw
		)


def flush_settings_cache():
	"""Immediately drop the ``Passkey Settings`` document-cache entry.

	``frappe.clear_document_cache`` deletes the redis key once, but ALSO schedules
	the same delete on ``db.after_commit``/``after_rollback``. The test runner rolls
	each test back to a savepoint, and ``after_rollback`` fires only on a FULL
	rollback — so a document-cache entry populated from in-transaction (or a
	committed-poisoned) read can survive between tests and make a settings-dependent
	test read the wrong modes ("Passkeys are not enabled" while its setUp set them
	on). Deleting the key directly here keeps the invalidation immediate, not
	deferred, so suites stay deterministic even on a poisoned local site.
	"""
	frappe.clear_document_cache("Passkey Settings", "Passkey Settings")
	frappe.cache.delete_value("document_cache::Passkey Settings::Passkey Settings")


def is_signed_out_by_frappe(exc) -> bool:
	"""Run ``exc`` through Frappe's real request error handler and report whether it
	deletes the session cookie."""
	from frappe.app import handle_exception
	from frappe.auth import CookieManager, LoginManager
	from frappe.utils import set_request

	set_request(method="POST", path="/api/method/passkeys.error_probe")
	frappe.local.cookie_manager = CookieManager()
	frappe.local.form_dict = frappe._dict()
	frappe.local.response = frappe._dict()
	sid = frappe.session.sid
	frappe.local.login_manager = LoginManager.__new__(LoginManager)
	try:
		raise exc
	except frappe.AuthenticationError:
		handle_exception(exc)  # inside ``except``: the handler formats the live traceback
	finally:
		del frappe.local.login_manager
		frappe.session.sid = sid
	return "sid" in frappe.local.cookie_manager.to_delete


def arrange_mode_floor(testcase):
	"""Satisfy the passkey-mode floor so a test may create ``passkey_only_login=1``.

	``WebAuthn User Handle`` refuses ``passkey_only_login`` unless a global passkey
	login mode is enabled (``lock_passkey_mode_floor``). A fresh site has both modes
	off, so a test that mints a flagged handle (or toggles ``set_passkey_only_login``)
	without arranging the floor throws. Snapshot ``login_with_passkey``, enable it,
	flush the settings cache, and register LIFO cleanup that restores the captured
	value first and flushes second — the same idiom as the arranged modules
	(``test_passkey_only_veto`` / ``test_lockout_race`` / ``test_passkey``)."""
	original = frappe.db.get_single_value("Passkey Settings", "login_with_passkey")
	testcase.addCleanup(flush_settings_cache)
	testcase.addCleanup(frappe.db.set_single_value, "Passkey Settings", "login_with_passkey", cint(original))
	frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
	flush_settings_cache()


def arrange_clean_login_policy(testcase):
	"""Pin ``disable_user_pass_login=0`` for a test that removes or disables a user's
	last enabled credential.

	The last-login-method guard (``_guard_last_login_method``) refuses dropping the
	final enabled credential of a user while site-wide ``disable_user_pass_login`` is
	on. An earlier module can leave that setting on — committed past the runner's
	per-test rollback, or merely cached on ``frappe.local.system_settings`` (which the
	rollback does not clear, and which ``flush_settings_cache`` does not touch). A test
	that deletes a credential as arrangement, without pinning the setting, then trips
	the guard under whatever test order the active Frappe branch happens to pick — the
	upstream-drift failure this closes. Snapshot the current value, force it off AND
	bust both caches, and register a cache-busting restore — the same no-commit idiom as
	``arrange_mode_floor``. Do NOT commit here: a committing cleanup would persist any
	other pending write in the test (e.g. a sibling ``or 0`` restore) past the rollback
	and leak it into later modules."""
	original = frappe.db.get_single_value("System Settings", "disable_user_pass_login")

	def _set(value):
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", value)
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None  # bust the request-local singles cache

	testcase.addCleanup(_set, cint(original))
	_set(0)


def arrange_saveable_system_settings(testcase):
	"""Fill System Settings' mandatory ``language`` / ``time_zone`` if blank, so a test
	may ``save()`` the document.

	A site created without the setup wizard (CI's fresh site) leaves both empty, and
	every System Settings save then raises ``MandatoryError`` — which a test expecting
	a floor's ``ValidationError`` would otherwise accept by accident. The fill values
	are Frappe's own fallbacks for the blank fields, so runtime behaviour is unchanged.
	Commits both the fill and the restore: the concurrency tests save from separate
	connections, and a committed fill must not outlive the test."""
	fallbacks = {"language": "en", "time_zone": "Asia/Kolkata"}
	blank = [field for field in fallbacks if not frappe.db.get_single_value("System Settings", field)]
	if not blank:
		return

	def _set(values):
		for field, value in values.items():
			frappe.db.set_single_value("System Settings", field, value)
		frappe.db.commit()
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None

	testcase.addCleanup(_set, dict.fromkeys(blank))
	_set({field: fallbacks[field] for field in blank})
