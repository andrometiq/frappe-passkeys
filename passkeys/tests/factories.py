# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Shared row factories for the test battery. Not a test module."""

import base64
import hashlib
import secrets

import frappe


def make_user() -> str:
	email = f"passkey-test-{frappe.generate_hash(length=8)}@example.com"
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": "Passkey",
			"last_name": "Test",
			"send_welcome_email": 0,
		}
	)
	user.flags.no_welcome_mail = True
	user.insert(ignore_permissions=True)
	return user.name


def make_credential(user: str, **overrides):
	raw_id = secrets.token_bytes(32)
	doc = frappe.get_doc(
		{
			"doctype": "WebAuthn Credential",
			"user": user,
			"label": "Test Passkey",
			"credential_id": base64.urlsafe_b64encode(raw_id).rstrip(b"=").decode(),
			"credential_id_sha256": hashlib.sha256(raw_id).hexdigest(),
			"public_key": base64.urlsafe_b64encode(secrets.token_bytes(77)).rstrip(b"=").decode(),
			**overrides,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc


def make_handle(user: str, **overrides):
	doc = frappe.get_doc(
		{
			"doctype": "WebAuthn User Handle",
			"user": user,
			"handle": base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode(),
			**overrides,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc
