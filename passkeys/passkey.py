# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted passkey endpoints (folds into ``frappe/passkey.py`` on the core
merge). The ceremony endpoints arrive with later build phases; this module
holds the typed-error wire contract (DESIGN-v1 §3) and the User cascade."""

import frappe

# Typed-error wire contract (§3): every typed error is an exception class —
# frappe's `report_error` emits the class name as `exc_type`, which is the wire
# value clients match on. Structured payloads ride `frappe.local.response`
# keys set before raising, never the translated message text.


class CeremonyExpired(frappe.AuthenticationError):
	"""Single-use state consumed, expired, evicted, or never existed (§4.2)."""


class UnknownCredential(frappe.AuthenticationError):
	"""Assertion references no known credential; feeds the Signal API (§3.1)."""


class UVSetupRequired(frappe.AuthenticationError):
	"""UV=1 assertion against a credential with uv_initialized=0 (§3.4/§3.7)."""


class PasskeyConfirmationRequired(frappe.AuthenticationError):
	"""A `@passkey_protected` action needs a fresh confirmation grant (§7.2)."""


class PasskeyServedByCore(frappe.ValidationError):
	"""Every app endpoint refuses when core serves passkeys natively (§11)."""

	http_status_code = 417


def cascade_delete_user_artifacts(doc, method=None):
	"""User on_trash: drop the user's credential and handle rows (§2.2)."""
	for doctype in ("WebAuthn Credential", "WebAuthn User Handle"):
		frappe.db.delete(doctype, {"user": doc.name})
