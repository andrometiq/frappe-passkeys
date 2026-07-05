# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Test base-class shim (§12.2): `IntegrationTestCase` on v16+/develop,
`FrappeTestCase` on v15 — without it the v15 CI leg fails at import."""

try:
	from frappe.tests import IntegrationTestCase
except ImportError:  # v15
	from frappe.tests.utils import FrappeTestCase as IntegrationTestCase

__all__ = ["IntegrationTestCase"]
