# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Install / uninstall / migrate guards.

Hook-path import discipline: this module MUST NOT import the
``webauthn`` library, directly or transitively."""

import hashlib
import hmac
import importlib
import importlib.util
import json
import os
import tempfile

import frappe
from frappe import _
from frappe.utils import cint, now, now_datetime

# Minimum safe Frappe per major line. 15.108.0 / 16.18.3 close CVE-2026-47194
# (host-header poisoning of magic/passwordless login links → account takeover) and
# subsume the crypto floor the webauthn library needs (cryptography>=46, pyOpenSSL>=26),
# which those lines first shipped. The check runs at install time only (before_install).
FRAPPE_VERSION_FLOORS = {15: (15, 108, 0), 16: (16, 18, 3)}
FRAPPE_VERSION_FLOOR_DEFAULT = (15, 108, 0)  # develop / newer majors (17.x is already post-fix)
DEFAULTS_PARENT = "__passkeys"

# The legacy "My Passkeys" avatar-menu item we used to sync into Navbar Settings.
# Passkey management now lives in the User-form "Passkeys" section, so the app no
# longer declares a standard_navbar_items hook; this action string is how both
# after_migrate and before_uninstall find and remove the previously-synced item.
NAVBAR_ITEM_ACTION = "frappe.passkeys.manage.openManagerDialog()"


def before_install():
	"""The abort-capable gate: a raise here leaves zero site state, while an
	`after_install` raise would leave a half-installed, registered app."""
	if core_module_present() or is_core_native():
		frappe.throw(
			_(
				"This Frappe installation serves passkeys natively (frappe.passkey). The passkeys app is an upgrade vehicle for sites that predate the native implementation — it cannot be freshly installed on top of it."
			)
		)
	check_frappe_version()


def after_install():
	_ensure_settings_defaults()
	ensure_enforcement_defaults()
	cleanup_legacy_registry_property_setter()
	sync_standard_navbar_items()
	sync_user_form_section()


def before_uninstall():
	"""Blocking lockout guard; then export the credential tables (the uninstall is
	about to drop them, so this makes removal non-destructive) before deleting the
	app's DefaultValue rows (not module-linked — nothing else ever cleans them) and
	legacy UI customizations, so a reinstall is a true fresh start."""
	_block_uninstall_lockout()
	_export_credentials_on_uninstall()
	frappe.db.delete("DefaultValue", {"parent": DEFAULTS_PARENT})
	cleanup_legacy_registry_property_setter()
	_remove_navbar_item()
	_remove_user_form_section()


_CORE_NATIVE: bool | None = None
CORE_HANDOVER_CAPABILITY = "frappe-passkeys-app-handover-v1"

# Cache key for the one-time dormant-shell advisory. Same cache-flag idiom
# as passkey._observe_2fa_floor_desync's once-daily observer.
_DORMANT_ADVISORY_KEY = "passkeys:dormant_uninstall_advisory"


def core_module_present() -> bool:
	"""Whether this Frappe tree contains any native passkey module."""
	return importlib.util.find_spec("frappe.passkey") is not None


def is_core_native() -> bool:
	"""Whether core explicitly implements the complete app-handover contract.

	Cached once per process ("checked once per process, cached") — every
	dormant-shell guard queries this switch on every hook + endpoint, so after the
	first capability check it must be O(1). Mere module presence is insufficient:
	a partial native implementation must never silence the installed app globally.
	The native module opts in with ``FRAPPE_PASSKEYS_APP_HANDOVER`` equal to
	:data:`CORE_HANDOVER_CAPABILITY`."""
	global _CORE_NATIVE
	if _CORE_NATIVE is None:
		if not core_module_present():
			_CORE_NATIVE = False
		else:
			try:
				module = importlib.import_module("frappe.passkey")
			except Exception:
				_CORE_NATIVE = False
			else:
				_CORE_NATIVE = (
					getattr(module, "FRAPPE_PASSKEYS_APP_HANDOVER", None) == CORE_HANDOVER_CAPABILITY
				)
	return _CORE_NATIVE


def dormant() -> bool:
	"""The runtime dormant-shell switch shared by every hook and endpoint guard:
	``True`` iff core advertises the complete handover capability, emitting the
	one-time uninstall advisory on the first engagement.

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
	parsed = _version_tuple(current)
	floor = FRAPPE_VERSION_FLOORS.get(parsed[0], FRAPPE_VERSION_FLOOR_DEFAULT)
	if parsed < floor:
		floor_str = ".".join(str(part) for part in floor)
		frappe.throw(
			_(
				"The passkeys app requires Frappe {0} or newer on this line (found {1}): older releases are exposed to CVE-2026-47194 (host-header poisoning of login links) and lack cryptography>=46.0.0 / pyOpenSSL>=26.0.0."
			).format(floor_str, current)
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
# Legacy registry Property Setter cleanup
# ---------------------------------------------------------------------------
# An earlier development build could create a "Passkey" option in the closed
# two_factor_method Select. No released Frappe branch exposes the proposed provider
# registry, so migrations retain only the idempotent cleanup needed by affected sites.


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


def _registry_property_setter_filters() -> dict:
	return {
		"doc_type": "System Settings",
		"field_name": "two_factor_method",
		"property": "options",
		"module": "Passkeys",
	}


def cleanup_legacy_registry_property_setter():
	"""Remove the obsolete development-build customization, if present."""
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
# in a non-deterministic spot. Programmatic (not a fixtures/ fixture) because it is
# gated on is_core_native(): a dormant/native site drops it, where a fixture would
# resync unconditionally. Install adds, after_migrate syncs, before_uninstall removes.
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
	stays schema-clean)."""
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
					# Collapsible: the section renders collapsed by default (Frappe's
					# refresh_section_collapse collapses a collapsible section with no
					# mandatory fields), so passkey management stays one click away
					# without adding vertical noise to My Settings. create_custom_fields
					# runs with update=True on after_migrate, so existing sites pick this
					# up on the next migrate.
					"collapsible": 1,
					# module set so core's uninstaller also cleans it (mirrors the
					# module ownership); before_uninstall removes it explicitly too.
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
# serialises both tables to one site-bound, HMAC-authenticated JSON file in the
# site's private files and prints its path. `import_credentials` restores the rows
# on an empty reinstall (an explicit override is required to merge with live data).
# When Frappe core ships native passkeys this same
# export is the migration seed; the exact field mapping is written once core's schema
# exists (see docs/install.md).

CREDENTIAL_EXPORT_SCHEMA = "frappe-passkeys/credential-export"
CREDENTIAL_EXPORT_VERSION = 2
CREDENTIAL_EXPORT_SIGNATURE_ALG = "HMAC-SHA256"


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

	The payload is bound to this site and authenticated with its encryption key,
	then written atomically with mode 0600. ``path`` defaults to a timestamped file
	in the site's private files."""
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
	payload["signature"] = {
		"alg": CREDENTIAL_EXPORT_SIGNATURE_ALG,
		"value": _export_signature(payload),
	}
	_write_private_json_atomic(path, payload)
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


def import_credentials(
	path: str, *, allow_existing: bool = False, allow_unsigned_legacy: bool = False
) -> dict:
	"""Restore rows written by :func:`export_credentials` after a reinstall.

	By default the destination must contain no passkey rows. ``allow_existing=True``
	enables an operator-reviewed merge where matching credentials/handles are skipped.
	Exports from app version 1 were unsigned; they are refused unless the operator has
	reviewed the file and explicitly passes ``allow_unsigned_legacy=True``.
	Credentials are restored before handles so a ``passkey_only_login`` handle clears
	its *enabled-credential* floor; its *login-mode* floor is a site-wide precondition
	the caller must satisfy first (see the up-front refusal below). Returns a created /
	skipped / rejected summary.

	Console-only by design (never whitelisted) — but a *crafted* export file must not be
	able to bind a public key to an account of the attacker's choosing, so every row is
	validated before restore:

	* the row's ``user`` must exist as an **enabled** User (a row for a missing or
	  disabled user is rejected);
	* the user's WebAuthn User Handle must be **consistent** — an export handle that
	  disagrees with the one already on the site, or that collides with another user's
	  handle, is a key-substitution attempt and rejects every row for that user; and a
	  credential whose user would have no handle at all (none on the site, none in the
	  export) is rejected too.

	Rejected rows are counted, listed for the operator, and returned under ``rejected``;
	the valid remainder is still imported."""
	with open(path, encoding="utf-8") as fh:
		data = json.load(fh)
	_validate_export(data, path, allow_unsigned_legacy=allow_unsigned_legacy)
	if data.get("version") == 1:
		print(f"passkeys: WARNING: importing explicitly approved unsigned legacy export -> {path}")
	if not allow_existing and (
		frappe.db.count("WebAuthn Credential") or frappe.db.count("WebAuthn User Handle")
	):
		frappe.throw(
			_(
				"Refusing to merge a credential export into live passkey data. Import into an empty installation, or pass allow_existing=True after reviewing conflicts."
			)
		)

	# Up-front login-mode precondition. A ``passkey_only_login`` handle asserts its user
	# MUST use a passkey as first factor, which is only viable while a passkey login mode
	# is enabled site-wide. A fresh reinstall lands with every mode off, so restoring such
	# a handle would trip its mode-floor validator mid-restore (after credential rows were
	# already inserted) and — if forced past it — recreate a user who is vetoed off password
	# login yet cannot use a passkey: a lockout. Refuse before touching any row, with the
	# exact remedy, rather than failing partway with a bare ValidationError.
	from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import lock_passkey_mode_floor

	new_passkey_only = sorted(
		{
			row.get("user")
			for row in data.get("user_handles", [])
			if cint(row.get("passkey_only_login"))
			and not frappe.db.exists("WebAuthn User Handle", {"user": row.get("user")})
		}
	)
	if new_passkey_only and not lock_passkey_mode_floor():
		frappe.throw(
			_(
				"This export restores passkey-only user(s) ({0}), but no passkey login mode is enabled on this site. "
				"Enable 'Login with Passkey' in Passkey Settings before importing, or those users would be locked out."
			).format(", ".join(new_passkey_only))
		)

	summary = {
		"credentials_created": 0,
		"credentials_skipped": 0,
		"credentials_rejected": 0,
		"handles_created": 0,
		"handles_skipped": 0,
		"handles_rejected": 0,
		"rejected": [],
	}

	credential_rows = data.get("credentials", [])
	handle_rows = data.get("user_handles", [])

	def _reject(kind: str, user, reason: str) -> None:
		summary[f"{kind}_rejected"] += 1
		summary["rejected"].append(f"{kind}: user={user!r}: {reason}")

	def _user_enabled(user) -> bool:
		return bool(user) and bool(frappe.db.get_value("User", user, "enabled"))

	# A user whose export handle disagrees with the site's live handle for that user — or
	# whose export handle value already belongs to a DIFFERENT user — is a substitution
	# attempt: reject every row (credential + handle) for that user.
	export_handle = {row.get("user"): row.get("handle") for row in handle_rows}
	handle_users = set(export_handle)
	mismatched_users = set()
	for user, handle in export_handle.items():
		existing = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
		if existing and existing != handle:
			mismatched_users.add(user)
			continue
		other = frappe.db.get_value("WebAuthn User Handle", {"handle": handle}, "user") if handle else None
		if other and other != user:
			mismatched_users.add(user)

	for row in credential_rows:
		user = row.get("user")
		if not _user_enabled(user):
			_reject("credentials", user, "no such enabled User")
			continue
		if user in mismatched_users:
			_reject("credentials", user, "user handle mismatch")
			continue
		# every credential must land on a user with a consistent handle — one already on
		# the site, or one this same import will create.
		if user not in handle_users and not frappe.db.exists("WebAuthn User Handle", {"user": user}):
			_reject("credentials", user, "no matching WebAuthn User Handle")
			continue
		existing_name = frappe.db.get_value(
			"WebAuthn Credential", {"credential_id_sha256": row.get("credential_id_sha256")}, "name"
		)
		if existing_name:
			if _existing_row_matches("WebAuthn Credential", existing_name, row):
				summary["credentials_skipped"] += 1
			else:
				_reject("credentials", user, "existing credential conflicts with export")
			continue
		_restore_row("WebAuthn Credential", row)
		summary["credentials_created"] += 1

	for row in handle_rows:
		user = row.get("user")
		if not _user_enabled(user):
			_reject("handles", user, "no such enabled User")
			continue
		if user in mismatched_users:
			_reject("handles", user, "user handle mismatch")
			continue
		existing_name = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "name")
		if existing_name:
			if _existing_row_matches("WebAuthn User Handle", existing_name, row):
				summary["handles_skipped"] += 1
			else:
				_reject("handles", user, "existing user handle conflicts with export")
			continue
		_restore_row("WebAuthn User Handle", row)
		summary["handles_created"] += 1

	frappe.db.commit()

	if summary["rejected"]:
		print(f"passkeys: import_credentials rejected {len(summary['rejected'])} row(s):")
		for line in summary["rejected"]:
			print(f"passkeys:   {line}")

	return summary


def _export_signature(payload: dict) -> str:
	unsigned = {key: value for key, value in payload.items() if key != "signature"}
	# Normalize Frappe datetime/value types first, then produce a deterministic
	# byte representation for HMAC verification.
	normalized = json.loads(frappe.as_json(unsigned))
	message = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
	return hmac.new(_export_signing_key(), message, hashlib.sha256).hexdigest()


def _export_signing_key() -> bytes:
	key = frappe.conf.get("encryption_key")
	if not key:
		frappe.throw(_("This site has no encryption_key; a credential export cannot be authenticated."))
	return b"frappe-passkeys:credential-export:v2\x00" + str(key).encode()


def _validate_export(data, path: str, *, allow_unsigned_legacy: bool = False) -> None:
	if not isinstance(data, dict) or data.get("schema") != CREDENTIAL_EXPORT_SCHEMA:
		frappe.throw(_("{0} is not a passkeys credential export.").format(path))
	version = data.get("version")
	if version == 1 and not allow_unsigned_legacy:
		frappe.throw(
			_(
				"{0} is an unsigned legacy passkeys export. Review its contents and site provenance, then pass allow_unsigned_legacy=True to import it explicitly."
			).format(path)
		)
	if version not in (1, CREDENTIAL_EXPORT_VERSION):
		frappe.throw(_("{0} uses an unsupported passkeys export version.").format(path))
	if data.get("site") != frappe.local.site:
		frappe.throw(_("{0} belongs to a different site.").format(path))
	if version == CREDENTIAL_EXPORT_VERSION:
		signature = data.get("signature")
		if not isinstance(signature, dict) or signature.get("alg") != CREDENTIAL_EXPORT_SIGNATURE_ALG:
			frappe.throw(_("{0} has no supported export signature.").format(path))
		expected = _export_signature(data)
		if not hmac.compare_digest(str(signature.get("value") or ""), expected):
			frappe.throw(_("{0} failed credential-export integrity verification.").format(path))
	credentials = data.get("credentials")
	handles = data.get("user_handles")
	counts = data.get("counts")
	if not isinstance(credentials, list) or not isinstance(handles, list) or not isinstance(counts, dict):
		frappe.throw(_("{0} has an invalid credential-export structure.").format(path))
	if counts.get("credentials") != len(credentials) or counts.get("user_handles") != len(handles):
		frappe.throw(_("{0} has inconsistent credential-export counts.").format(path))


def _write_private_json_atomic(path: str, payload: dict) -> None:
	"""Write mode-0600 JSON and atomically replace the requested destination."""
	directory = os.path.dirname(os.path.abspath(path))
	os.makedirs(directory, mode=0o700, exist_ok=True)
	fd, temporary = tempfile.mkstemp(prefix=".passkeys-export-", suffix=".tmp", dir=directory)
	try:
		os.fchmod(fd, 0o600)
		with os.fdopen(fd, "w", encoding="utf-8") as fh:
			fd = -1
			fh.write(frappe.as_json(payload, indent=2))
			fh.flush()
			os.fsync(fh.fileno())
		os.replace(temporary, path)
		os.chmod(path, 0o600)
	except Exception:
		if fd >= 0:
			os.close(fd)
		try:
			os.unlink(temporary)
		except FileNotFoundError:
			pass
		raise


def _restore_row(doctype: str, row: dict) -> None:
	doc = frappe.new_doc(doctype)
	allowed = set(_exportable_fieldnames(doctype))
	for field, value in row.items():
		if field in allowed:
			doc.set(field, value)
	doc.flags.ignore_permissions = True
	doc.insert()


def _existing_row_matches(doctype: str, name: str, exported: dict) -> bool:
	"""Return whether an idempotent merge target is byte-for-byte equivalent.

	Skipping by identifier alone can silently retain a weaker sign counter, a
	different public key, or a cleared passkey-only flag. Normalize through
	Frappe's JSON encoder so database datetime/value objects compare to the loaded
	export representation without weakening field coverage.
	"""
	fields = _exportable_fieldnames(doctype)
	existing = frappe.db.get_value(doctype, name, fields, as_dict=True)
	if not existing:
		return False
	expected = {field: exported.get(field) for field in fields}
	return json.loads(frappe.as_json(existing)) == json.loads(frappe.as_json(expected))
