# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Install / uninstall / migrate guards.

Hook-path import discipline: this module MUST NOT import the
``webauthn`` library, directly or transitively."""

import importlib.util
import json

import frappe
from frappe import _
from frappe.utils import cint, now, now_datetime

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
	ensure_enforcement_defaults()
	sync_registry_fixture()
	sync_standard_navbar_items()
	sync_user_form_section()


def before_uninstall():
	"""Blocking lockout guard; then export the credential tables (the uninstall is
	about to drop them, so this makes removal non-destructive) before deleting the
	app's DefaultValue rows (not module-linked — nothing else ever cleans them) and
	the registry Property Setter, so a reinstall is a true fresh start."""
	_block_uninstall_lockout()
	_export_credentials_on_uninstall()
	frappe.db.delete("DefaultValue", {"parent": DEFAULTS_PARENT})
	_remove_registry_property_setter()
	_remove_navbar_item()
	_remove_user_form_section()


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


def ensure_enforcement_defaults():
	"""Seed the break-glass exempt role (``System Manager``) into Passkey Settings
	when the exempt-roles table is empty, so an administrator can never lock
	themselves out the moment enforcement is turned on. Idempotent — safe to call on
	install and from the fold-nudge migration patch."""
	doc = frappe.get_doc("Passkey Settings")
	if doc.get("passkey_enforce_exempt_roles"):
		return
	doc.append("passkey_enforce_exempt_roles", {"role": "System Manager"})
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


# ---------------------------------------------------------------------------
# User-form "Passkeys" section (programmatic Custom Fields — NOT a fixtures/ fixture)
# ---------------------------------------------------------------------------
# The section is placed DETERMINISTICALLY, right after the User form's password
# ("Change Password") / security area, via a Custom Field Section Break + an HTML
# wrapper — replacing the old dashboard section that appended at the END of the form
# in a non-deterministic spot. Programmatic (not a fixtures/ fixture) for the same two
# reasons as the registry Property Setter: it is gated on is_core_native() (a dormant /
# native site drops it, where a fixture would resync unconditionally), and the lifecycle
# mirrors that setter — install adds, after_migrate syncs, before_uninstall removes.
# The client glue (user_passkeys.js) renders into the HTML wrapper and collapses the
# (empty) section when no passkey mode is active, so it never shows an empty header.

USER_FORM_SECTION_FIELD = "passkeys_section"
USER_FORM_HTML_FIELD = "passkeys_html"

# Anchor priority: the LAST field of the User "Change Password" section on
# v15/v16/develop (verified against all three benches), so the Passkeys section lands
# cleanly right AFTER that section — the natural neighbour of where a user manages their
# password. Each fallback is a field of the same security/password area, present on all
# three, used only if a future Frappe drops the primary anchor.
_USER_FORM_ANCHOR_CANDIDATES = (
	"redirect_url",
	"last_password_reset_date",
	"logout_all_sessions",
	"change_password",
)


def sync_user_form_section():
	"""after_install + after_migrate: create the User-form "Passkeys" section Custom
	Fields iff core is not passkey-native; remove them otherwise (a dormant / native site
	stays schema-clean). Mirrors :func:`sync_registry_fixture`."""
	if is_core_native():
		_remove_user_form_section()
	else:
		_create_user_form_section()


def _user_form_anchor() -> str:
	"""The first candidate anchor present on the running Frappe's User form. Falls back to
	the primary name if none is found (Frappe then appends the field — a defined, if less
	tidy, placement) so a schema drift never raises during install/migrate."""
	meta = frappe.get_meta("User")
	for fieldname in _USER_FORM_ANCHOR_CANDIDATES:
		if meta.has_field(fieldname):
			return fieldname
	return _USER_FORM_ANCHOR_CANDIDATES[0]


def _create_user_form_section():
	# Lazy import keeps the hook-path import discipline (no webauthn transitively); this is
	# pure core frappe. Section Break + HTML are non-stored fieldtypes, so no column /
	# ALTER TABLE is created — the write stays transactional.
	from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

	create_custom_fields(
		{
			"User": [
				{
					"fieldname": USER_FORM_SECTION_FIELD,
					"label": "Passkeys",
					"fieldtype": "Section Break",
					"insert_after": _user_form_anchor(),
					# module set so core's uninstaller also cleans it (mirrors the
					# registry Property Setter); before_uninstall removes it explicitly too.
					"module": "Passkeys",
				},
				{
					"fieldname": USER_FORM_HTML_FIELD,
					"fieldtype": "HTML",
					"insert_after": USER_FORM_SECTION_FIELD,
					"module": "Passkeys",
				},
			]
		},
		update=True,
	)
	frappe.clear_cache(doctype="User")


def _remove_user_form_section():
	"""Delete the section Custom Fields (HTML first, then its Section Break). Idempotent;
	safe on sites that never had them."""
	removed = False
	for fieldname in (USER_FORM_HTML_FIELD, USER_FORM_SECTION_FIELD):
		name = frappe.db.get_value("Custom Field", {"dt": "User", "fieldname": fieldname})
		if name:
			frappe.delete_doc("Custom Field", name, ignore_permissions=True, force=True)
			removed = True
	if removed:
		frappe.clear_cache(doctype="User")


# ---------------------------------------------------------------------------
# Credential export / import — uninstall is never destructive
# ---------------------------------------------------------------------------
# A standard `uninstall-app` drops the WebAuthn Credential + WebAuthn User Handle
# tables, so every enrolled passkey would otherwise be lost. before_uninstall first
# serialises both tables — public-key material and metadata only; neither table
# stores a server-side secret — to one JSON file in the site's private files and
# prints its path. `import_credentials` restores the rows on a reinstall, idempotently
# keyed on credential_id_sha256. When Frappe core ships native passkeys this same
# export is the migration seed; the exact field mapping is written once core's schema
# exists (see docs/install.md).

CREDENTIAL_EXPORT_SCHEMA = "frappe-passkeys/credential-export"
CREDENTIAL_EXPORT_VERSION = 1


def _exportable_fieldnames(doctype: str) -> list[str]:
	"""The real stored fields of a doctype (layout breaks dropped), derived from meta
	so a later field addition is carried by export/import without editing this module."""
	return [
		df.fieldname
		for df in frappe.get_meta(doctype).fields
		if df.fieldtype not in ("Section Break", "Column Break", "HTML")
	]


def export_credentials(path: str | None = None) -> str | None:
	"""Serialise every WebAuthn Credential + WebAuthn User Handle row to one JSON file
	and return its path (``None`` when there is nothing to export).

	Only public-key material and metadata are written; neither table stores a
	server-side secret, so the file is safe to keep alongside a site backup. ``path``
	defaults to a timestamped file in the site's private files."""
	credentials = frappe.get_all(
		"WebAuthn Credential",
		fields=_exportable_fieldnames("WebAuthn Credential"),
		order_by="creation asc",
	)
	handles = frappe.get_all(
		"WebAuthn User Handle",
		fields=_exportable_fieldnames("WebAuthn User Handle"),
		order_by="creation asc",
	)
	if not credentials and not handles:
		return None

	if path is None:
		filename = "passkeys-credentials-{0}.json".format(now_datetime().strftime("%Y%m%d-%H%M%S"))
		path = frappe.get_site_path("private", "files", filename)

	payload = {
		"schema": CREDENTIAL_EXPORT_SCHEMA,
		"version": CREDENTIAL_EXPORT_VERSION,
		"exported_at": now(),
		"site": frappe.local.site,
		"counts": {"credentials": len(credentials), "user_handles": len(handles)},
		"credentials": credentials,
		"user_handles": handles,
	}
	with open(path, "w", encoding="utf-8") as fh:
		fh.write(frappe.as_json(payload, indent=2))
	return path


def _export_credentials_on_uninstall() -> None:
	"""before_uninstall step: export the credential tables (which the uninstall is
	about to drop) and print the path + the one-line restore recipe, so an operator
	can put the passkeys back after a reinstall."""
	path = export_credentials()
	if path is None:
		return
	print(f"passkeys: credentials exported before uninstall -> {path}")
	print("passkeys: to restore them after reinstalling, run in `bench --site <site> console`:")
	print(f'passkeys:   from passkeys.install import import_credentials; import_credentials("{path}")')


def import_credentials(path: str) -> dict:
	"""Restore rows written by :func:`export_credentials` after a reinstall.

	Idempotent and safe to re-run: a credential whose ``credential_id_sha256`` (or a
	user handle whose ``user``) already exists is skipped. Credentials are restored
	before handles so a ``passkey_only_login`` handle clears its enabled-credential
	floor. Returns a created/skipped summary."""
	with open(path, encoding="utf-8") as fh:
		data = json.load(fh)
	if data.get("schema") != CREDENTIAL_EXPORT_SCHEMA:
		frappe.throw(_("{0} is not a passkeys credential export.").format(path))

	summary = {
		"credentials_created": 0,
		"credentials_skipped": 0,
		"handles_created": 0,
		"handles_skipped": 0,
	}

	for row in data.get("credentials", []):
		if frappe.db.exists("WebAuthn Credential", {"credential_id_sha256": row.get("credential_id_sha256")}):
			summary["credentials_skipped"] += 1
			continue
		_restore_row("WebAuthn Credential", row)
		summary["credentials_created"] += 1

	for row in data.get("user_handles", []):
		if frappe.db.exists("WebAuthn User Handle", {"user": row.get("user")}):
			summary["handles_skipped"] += 1
			continue
		_restore_row("WebAuthn User Handle", row)
		summary["handles_created"] += 1

	frappe.db.commit()
	return summary


def _restore_row(doctype: str, row: dict) -> None:
	doc = frappe.new_doc(doctype)
	allowed = set(_exportable_fieldnames(doctype))
	for field, value in row.items():
		if field in allowed:
			doc.set(field, value)
	doc.flags.ignore_permissions = True
	doc.insert()
