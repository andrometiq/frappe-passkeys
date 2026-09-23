# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Typed wire errors and the dormant-shell endpoint guard.

Clients match on ``exc_type`` (the class name Frappe's ``report_error`` emits), never
on message text; structured payloads ride ``frappe.local.response`` keys set before
raising. Webauthn-free, and it imports only ``install``, so every layer can use it."""

import frappe
from frappe import _

from passkeys import install


class CeremonyExpired(frappe.AuthenticationError):
	"""Single-use state consumed, expired, evicted, or never existed."""


class UnknownCredential(frappe.AuthenticationError):
	"""Assertion references no known credential; feeds the Signal API."""


class UVSetupRequired(frappe.AuthenticationError):
	"""UV=1 assertion against a credential with uv_initialized=0."""


class PasskeyConfirmationRequired(frappe.AuthenticationError):
	"""A `@passkey_protected` action needs a fresh confirmation grant."""


class PasskeyServedByCore(frappe.ValidationError):
	"""Every app endpoint refuses when core serves passkeys natively."""

	http_status_code = 417


def refuse_if_core_native() -> None:
	"""The first guard on every whitelisted app endpoint: once core serves passkeys
	natively, raise the typed 417 so the two implementations never mint sessions or
	mutate credentials in parallel. Rides ``install.dormant``, so the first guarded hit
	also emits the one-time uninstall advisory."""
	if install.dormant():
		raise PasskeyServedByCore(_("This site serves passkeys natively."))
