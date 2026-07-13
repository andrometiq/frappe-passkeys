# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Test base-class shim: `IntegrationTestCase` on v16+/develop,
`FrappeTestCase` on v15 — without it the v15 CI leg fails at import."""

import frappe

try:
	from frappe.tests import IntegrationTestCase
except ImportError:  # v15
	from frappe.tests.utils import FrappeTestCase as IntegrationTestCase

__all__ = ["IntegrationTestCase", "WebAuthnAssertMixin", "flush_settings_cache"]


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
