# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Install / uninstall / migrate guards.

Hook-path import discipline: this module MUST NOT import the
``webauthn`` library, directly or transitively."""

import importlib.util

import frappe
from frappe import _
from frappe.utils import cint

FRAPPE_VERSION_FLOOR = (15, 107, 0)
DEFAULTS_PARENT = "__passkeys"

# The legacy "My Passkeys" avatar-menu item we used to sync into Navbar Settings.
# Passkey management now lives in the User-form "Passkeys" section, so the app no
# longer declares a standard_navbar_items hook; this action string is how both
# after_migrate and before_uninstall find and remove the previously-synced item.
NAVBAR_ITEM_ACTION = "frappe.passkeys.manage.openManagerDialog()"


def before_install():
	"""The abort-capable gate: a raise here leaves zero site state, while an
	`after_install` raise would leave a half-installed, registered app."""
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
	sync_standard_navbar_items()


def before_uninstall():
	"""Blocking lockout guard; then delete the app's DefaultValue rows (not
	module-linked — nothing else ever cleans them) and the registry Property
	Setter, so a reinstall is a true fresh start."""
	_block_uninstall_lockout()
	frappe.db.delete("DefaultValue", {"parent": DEFAULTS_PARENT})
	_remove_registry_property_setter()
	_remove_navbar_item()


_CORE_NATIVE: bool | None = None

# Cache key for the one-time dormant-shell advisory. Same cache-flag idiom
# as passkey._observe_2fa_floor_desync's once-daily observer.
_DORMANT_ADVISORY_KEY = "passkeys:dormant_uninstall_advisory"


def is_core_native() -> bool:
	"""Stage-2 detection: core owns passkeys when `frappe.passkey` exists.

	Cached once per process ("checked once per process, cached") — every
	dormant-shell guard queries this switch on every hook + endpoint, so after the
	first ``find_spec`` (which walks the import system) it must be O(1). The result
	is immutable for the life of the process: a running site cannot grow/lose
	``frappe.passkey`` without a restart."""
	global _CORE_NATIVE
	if _CORE_NATIVE is None:
		_CORE_NATIVE = importlib.util.find_spec("frappe.passkey") is not None
	return _CORE_NATIVE


def dormant() -> bool:
	"""The runtime dormant-shell switch shared by every hook and endpoint guard:
	``True`` iff core serves passkeys natively, emitting the one-time uninstall
	advisory on the first engagement.

	Kept distinct from :func:`is_core_native` (the pure predicate) because
	``before_install`` uses that predicate to REFUSE a fresh install — a context
	where an "app is dormant, uninstall it" advisory would be nonsense. Hooks call
	``if dormant(): return`` (a silent no-op — a hook that raises would break core
	logins); endpoints wrap it in ``passkey.refuse_if_core_native`` → 417."""
	if not is_core_native():
		return False
	_advise_dormant_once()
	return True


def _advise_dormant_once() -> None:
	"""One structured operator advisory the first time dormancy engages ("The
	app logs a one-time uninstall advisory"). Cache-flag idiom (cf.
	``passkey._observe_2fa_floor_desync``) so it fires once, never per request.
	Non-blocking — an advisory failure must never disturb the guarded surface that
	rides on it."""
	try:
		key = frappe.cache.make_key(_DORMANT_ADVISORY_KEY)
		if frappe.cache.get(key):
			return
		frappe.cache.set(key, "1")
		frappe.log_error(
			title="passkeys: dormant — core serves passkeys natively",
			message=(
				"This site serves passkeys natively (frappe.passkey), so the passkeys "
				"app has gone dormant: every whitelisted endpoint now returns HTTP 417 "
				"PasskeyServedByCore and every hook is a no-op. The app is an upgrade "
				"vehicle for sites that predate the native implementation and is now "
				"safe to uninstall (bench --site <site> uninstall-app passkeys)."
			),
		)
	except Exception:
		pass


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
	login modes OFF (installing is not enabling)."""
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
# registry Property Setter (programmatic — NOT a fixtures/ fixture)
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


def _remove_navbar_item():
	"""Delete the legacy "My Passkeys" Navbar Item, keyed on our own action string so
	nothing else is touched. Idempotent; safe on sites that never had it."""
	frappe.db.delete("Navbar Item", {"parent": "Navbar Settings", "action": NAVBAR_ITEM_ACTION})
	frappe.clear_document_cache("Navbar Settings", "Navbar Settings")


def sync_standard_navbar_items():
	"""after_migrate: clean up the legacy "My Passkeys" avatar-menu item on existing
	sites. Passkey management moved into the User-form "Passkeys" section, so the app
	no longer declares a ``standard_navbar_items`` hook.

	Remove the item we previously synced into Navbar Settings (idempotent — mirrors
	``before_uninstall``), then let core's idempotent sync (v16/develop) reconcile the
	remaining apps' standard items. v15 exposes no such core helper (and its destructive
	``add_standard_navbar_items`` must never be called from a migrate hook), so the
	explicit removal above is the whole story there.
	"""
	_remove_navbar_item()
	try:
		from frappe.core.doctype.navbar_settings.navbar_settings import sync_standard_items
	except ImportError:
		return  # v15: no idempotent core sync — the explicit removal above suffices
	sync_standard_items()


def two_factor_registry_available() -> bool:
	"""Stage-1 registry detection: keyed to a core symbol introduced by
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
