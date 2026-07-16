# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Non-whitelisted helpers for the CI app-lifecycle gate."""

import base64
import hashlib

import frappe

from passkeys.tests.factories import make_credential, make_handle

LIFECYCLE_USER = "passkey-lifecycle@example.com"
LIFECYCLE_LABEL = "Lifecycle Gate Passkey"
LIFECYCLE_CREDENTIAL_ID = base64.urlsafe_b64encode(b"frappe-passkeys-lifecycle-id").rstrip(b"=").decode()
LIFECYCLE_CREDENTIAL_SHA = hashlib.sha256(b"frappe-passkeys-lifecycle-id").hexdigest()
LIFECYCLE_PUBLIC_KEY = base64.urlsafe_b64encode(b"frappe-passkeys-lifecycle-public-key").rstrip(b"=").decode()
LIFECYCLE_HANDLE = (
	base64.urlsafe_b64encode(hashlib.sha512(b"frappe-passkeys-lifecycle-handle").digest())
	.rstrip(b"=")
	.decode()
)


def configure_lifecycle_mode() -> None:
	"""Keep passkey-only lifecycle data reachable before seed and import."""
	frappe.set_user("Administrator")
	settings = frappe.get_single("Passkey Settings")
	settings.login_with_passkey = 1
	settings.passkey_rp_id = "lifecycle.example.com"
	settings.passkey_origins = "https://lifecycle.example.com"
	settings.save(ignore_permissions=True)
	frappe.db.commit()


def seed_lifecycle_data() -> dict:
	configure_lifecycle_mode()
	if not frappe.db.exists("User", LIFECYCLE_USER):
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": LIFECYCLE_USER,
				"first_name": "Passkey",
				"last_name": "Lifecycle",
				"send_welcome_email": 0,
			}
		)
		user.flags.no_welcome_mail = True
		user.insert(ignore_permissions=True)
	frappe.db.delete("WebAuthn Credential", {"user": LIFECYCLE_USER})
	frappe.db.delete("WebAuthn User Handle", {"user": LIFECYCLE_USER})
	credential = make_credential(
		LIFECYCLE_USER,
		label=LIFECYCLE_LABEL,
		sign_count=17,
		credential_id=LIFECYCLE_CREDENTIAL_ID,
		credential_id_sha256=LIFECYCLE_CREDENTIAL_SHA,
		public_key=LIFECYCLE_PUBLIC_KEY,
		transports='["internal", "hybrid"]',
		backup_eligible=1,
		backup_state=1,
		uv_initialized=1,
		discoverable="Yes",
		rp_id="lifecycle.example.com",
	)
	make_handle(LIFECYCLE_USER, handle=LIFECYCLE_HANDLE, passkey_only_login=1)
	frappe.db.commit()
	return {"credential_id_sha256": credential.credential_id_sha256}


def prepare_lifecycle_uninstall() -> None:
	"""Clear the live lockout flag only after the signed export captured it."""
	frappe.db.set_value(
		"WebAuthn User Handle",
		{"user": LIFECYCLE_USER},
		"passkey_only_login",
		0,
		update_modified=False,
	)
	frappe.db.commit()


def assert_lifecycle_data_restored() -> None:
	credential = frappe.db.get_value(
		"WebAuthn Credential",
		{"user": LIFECYCLE_USER},
		[
			"label",
			"sign_count",
			"credential_id",
			"credential_id_sha256",
			"public_key",
			"transports",
			"backup_eligible",
			"backup_state",
			"uv_initialized",
			"discoverable",
			"rp_id",
		],
		as_dict=True,
	)
	expected = {
		"label": LIFECYCLE_LABEL,
		"sign_count": 17,
		"credential_id": LIFECYCLE_CREDENTIAL_ID,
		"credential_id_sha256": LIFECYCLE_CREDENTIAL_SHA,
		"public_key": LIFECYCLE_PUBLIC_KEY,
		"transports": '["internal", "hybrid"]',
		"backup_eligible": 1,
		"backup_state": 1,
		"uv_initialized": 1,
		"discoverable": "Yes",
		"rp_id": "lifecycle.example.com",
	}
	if not credential or any(credential.get(field) != value for field, value in expected.items()):
		raise AssertionError("credential data was not restored exactly")
	handle = frappe.db.get_value(
		"WebAuthn User Handle",
		{"user": LIFECYCLE_USER},
		["handle", "passkey_only_login"],
		as_dict=True,
	)
	if not handle or handle.handle != LIFECYCLE_HANDLE or int(handle.passkey_only_login) != 1:
		raise AssertionError("user handle data was not restored exactly")
