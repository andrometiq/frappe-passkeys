# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Install / uninstall / migrate guards (DESIGN-v1 §14).

Hook-path import discipline (§1.3): this module MUST NOT import the
``webauthn`` library, directly or transitively."""

import importlib.util

import frappe
from frappe import _
from frappe.utils import cint

FRAPPE_VERSION_FLOOR = (15, 107, 0)
DEFAULTS_PARENT = "__passkeys"


def before_install():
	"""The abort-capable gate: a raise here leaves zero site state, while an
	`after_install` raise would leave a half-installed, registered app (§14)."""
	if is_core_native():
		frappe.throw(
			_(
				"This Frappe installation serves passkeys natively (frappe.passkey). The passkeys app is an upgrade vehicle for sites that predate the native implementation — it cannot be freshly installed on top of it."
			)
		)
	check_frappe_version()


def after_install():
	_ensure_settings_defaults()
	sync_registry_fixture()


def before_uninstall():
	"""Blocking lockout guard; then delete the app's DefaultValue rows (not
	module-linked — nothing else ever cleans them) and the registry Property
	Setter, so a reinstall is a true fresh start (§14)."""
	_block_uninstall_lockout()
	frappe.db.delete("DefaultValue", {"parent": DEFAULTS_PARENT})
	_remove_registry_property_setter()


def is_core_native() -> bool:
	"""Stage-2 detection (§11): core owns passkeys when `frappe.passkey` exists."""
	return importlib.util.find_spec("frappe.passkey") is not None


def check_frappe_version(current: str | None = None):
	current = current or frappe.__version__
	if _version_tuple(current) < FRAPPE_VERSION_FLOOR:
		floor = ".".join(str(part) for part in FRAPPE_VERSION_FLOOR)
		frappe.throw(
			_(
				"The passkeys app requires Frappe {0} or newer (found {1}): the webauthn library needs cryptography>=46.0.0 and pyOpenSSL>=26.0.0, which older releases do not ship."
			).format(floor, current)
		)


def _version_tuple(version: str) -> tuple[int, int, int]:
	parts = version.split("+", 1)[0].split("-", 1)[0].split(".")
	numbers = [int(part) if part.isdigit() else 0 for part in parts[:3]]
	while len(numbers) < 3:
		numbers.append(0)
	return tuple(numbers)


def _block_uninstall_lockout():
	# (a) username/password login disabled and no other method would survive
	# (census mirrors core's validate_user_pass_login allowlist)
	if cint(frappe.db.get_single_value("System Settings", "disable_user_pass_login")):
		social_login_enabled = frappe.db.exists("Social Login Key", {"enable_social_login": 1})
		ldap_enabled = cint(frappe.db.get_single_value("LDAP Settings", "enabled"))
		email_link_enabled = cint(frappe.db.get_single_value("System Settings", "login_with_email_link"))
		if not (social_login_enabled or ldap_enabled or email_link_enabled):
			frappe.throw(
				_(
					"Cannot uninstall passkeys: username/password login is disabled and no other login method (Social Login, LDAP, Login with Email Link) is enabled. Enable one in System Settings first."
				)
			)

	# (b) passkey-only users would be locked out
	flagged = frappe.get_all("WebAuthn User Handle", filters={"passkey_only_login": 1}, pluck="user")
	if flagged:
		frappe.throw(
			_(
				"Cannot uninstall passkeys: these users allow passkey login only and would be locked out: {0}. Clear 'Passkey Only Login' on their WebAuthn User Handle records first (WebAuthn User Handle list in Desk, or bench console)."
			).format(", ".join(flagged))
		)


def _ensure_settings_defaults():
	"""Persist the Passkey Settings Single with its declared defaults — all
	login modes OFF (installing is not enabling, §9.1)."""
	doc = frappe.get_doc("Passkey Settings")
	for df in doc.meta.fields:
		if df.fieldtype in ("Section Break", "Column Break", "HTML"):
			continue
		if df.default is not None and doc.get(df.fieldname) is None:
			doc.set(df.fieldname, df.default)
	doc.flags.ignore_permissions = True
	doc.flags.ignore_mandatory = True
	doc.save()


# ---------------------------------------------------------------------------
# registry Property Setter (programmatic — NOT a fixtures/ fixture; §14)
# ---------------------------------------------------------------------------
# frappe's installer runs sync_fixtures unconditionally, so a fixtures-machinery
# Property Setter would land on v15/v16, where two_factor_method is a closed
# dispatch and a dangling "Passkey" option breaks 2FA login site-wide.


def sync_registry_fixture():
	"""after_install + after_migrate: create the `Passkey` two_factor_method
	option iff the Stage-1 registry exists and core is not passkey-native;
	remove it explicitly otherwise (downgrade/revert stays clean)."""
	if two_factor_registry_available() and not is_core_native():
		_create_registry_property_setter()
	else:
		_remove_registry_property_setter()


def two_factor_registry_available() -> bool:
	"""Stage-1 registry detection (§6.5): keyed to a core symbol introduced by
	the upstream pluggable-2FA PR — the exact ``frappe.twofactor`` attribute is
	pinned when that PR is authored (build phase 4). Never ``get_hooks`` (the
	app's own static entry would self-poison it) and never version strings."""
	return False


def _registry_property_setter_filters() -> dict:
	return {
		"doc_type": "System Settings",
		"field_name": "two_factor_method",
		"property": "options",
		"module": "Passkeys",
	}


def _create_registry_property_setter():
	if frappe.db.exists("Property Setter", _registry_property_setter_filters()):
		return
	field = frappe.get_meta("System Settings").get_field("two_factor_method")
	options = [option for option in (field.options or "").split("\n") if option]
	if "Passkey" not in options:
		options.append("Passkey")
	frappe.get_doc(
		{
			"doctype": "Property Setter",
			"doctype_or_field": "DocField",
			"doc_type": "System Settings",
			"field_name": "two_factor_method",
			"property": "options",
			"property_type": "Text",
			"value": "\n".join(options),
			# module set so core's uninstaller also cleans it — a moduleless
			# row survives uninstall forever
			"module": "Passkeys",
		}
	).insert(ignore_permissions=True)
	frappe.clear_cache(doctype="System Settings")


def _remove_registry_property_setter():
	names = frappe.get_all("Property Setter", filters=_registry_property_setter_filters(), pluck="name")
	for name in names:
		frappe.delete_doc("Property Setter", name, ignore_permissions=True, force=True)
	if names:
		frappe.clear_cache(doctype="System Settings")
