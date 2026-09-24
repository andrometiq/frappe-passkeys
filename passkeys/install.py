# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Install / uninstall / migrate hooks, the native-core handover switch, and the
credential export / import that makes an uninstall reversible.

Hook path: this module must not import ``webauthn``, directly or transitively."""

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

DEFAULTS_PARENT = "__passkeys"
CORE_HANDOVER_CAPABILITY = "frappe-passkeys-app-handover-v1"
_DORMANT_ADVISORY_KEY = "passkeys:dormant_uninstall_advisory"
_CORE_NATIVE: bool | None = None

USER_FORM_SECTION_FIELD = "passkeys_section"
USER_FORM_HTML_FIELD = "passkeys_html"
# The last field of the User form's "Change Password" section on v15, v16 and develop.
USER_FORM_ANCHOR = "redirect_url"

CREDENTIAL_EXPORT_SCHEMA = "frappe-passkeys/credential-export"
CREDENTIAL_EXPORT_VERSION = 2
CREDENTIAL_EXPORT_SIGNATURE_ALG = "HMAC-SHA256"


# Oldest Frappe per major line with the fix for GHSA-3w78-3cj3-p949. Bench only warns
# on pyproject's frappe-dependencies, so the floor is enforced here.
FRAPPE_VERSION_FLOORS = {15: (15, 108, 0), 16: (16, 18, 3)}


def check_frappe_version(current: str | None = None) -> None:
	current = current or frappe.__version__
	parts = current.split("+", 1)[0].split("-", 1)[0].split(".")
	version = tuple(int(part) if part.isdigit() else 0 for part in [*parts, "0", "0"][:3])
	floor = FRAPPE_VERSION_FLOORS.get(version[0])
	if floor and version < floor:
		frappe.throw(
			_("The passkeys app needs Frappe {0} or later on this line; this site runs {1}.").format(
				".".join(str(part) for part in floor), current
			)
		)


def before_install():
	"""Refuse to install on a Frappe below the security floor or one that ships its own
	passkey module. Runs before install so a refusal leaves no half-installed app behind."""
	check_frappe_version()
	if core_module_present() or is_core_native():
		frappe.throw(
			_(
				"This Frappe installation serves passkeys natively (frappe.passkey). The passkeys app is an upgrade vehicle for sites that predate the native implementation — it cannot be freshly installed on top of it."
			)
		)


def after_install():
	# An empty Single loads its declared defaults; saving persists them for the
	# code that reads single values straight from the database.
	settings = frappe.get_single("Passkey Settings")
	settings.flags.ignore_permissions = True
	settings.flags.ignore_mandatory = True
	settings.save()
	sync_user_form_section()


def before_uninstall():
	"""Refuse an uninstall that would lock users out, export the credential tables the
	uninstall is about to drop, then remove what core's uninstaller leaves behind."""
	_block_uninstall_lockout()
	_export_credentials_on_uninstall()
	frappe.db.delete("DefaultValue", {"parent": DEFAULTS_PARENT})
	_remove_user_form_section()


# ---------------------------------------------------------------------------
# Native-core handover
# ---------------------------------------------------------------------------


def core_module_present() -> bool:
	"""Whether this Frappe tree contains any native passkey module."""
	return importlib.util.find_spec("frappe.passkey") is not None


def is_core_native() -> bool:
	"""Whether core implements the complete app-handover contract (its ``frappe.passkey``
	sets ``FRAPPE_PASSKEYS_APP_HANDOVER`` to :data:`CORE_HANDOVER_CAPABILITY`). Module
	presence alone is not enough: a partial native implementation must never silence
	the app. Cached per process; every dormancy guard calls it."""
	global _CORE_NATIVE
	if _CORE_NATIVE is None:
		_CORE_NATIVE = False
		if core_module_present():
			try:
				module = importlib.import_module("frappe.passkey")
			except Exception:
				pass
			else:
				_CORE_NATIVE = (
					getattr(module, "FRAPPE_PASSKEYS_APP_HANDOVER", None) == CORE_HANDOVER_CAPABILITY
				)
	return _CORE_NATIVE


def dormant() -> bool:
	"""The runtime switch behind every hook and endpoint guard: ``True`` once core
	serves passkeys natively. Hooks then return silently (a raising hook would break
	core logins); endpoints answer 417 via ``errors.refuse_if_core_native``. Logs a
	one-time uninstall advisory on first use."""
	if not is_core_native():
		return False
	_advise_dormant_once()
	return True


def _advise_dormant_once() -> None:
	# Never let the advisory disturb the guarded hook or endpoint that triggered it.
	try:
		key = frappe.cache.make_key(_DORMANT_ADVISORY_KEY)
		if frappe.cache.get(key):  # nosemgrep: frappe-cache-breaks-multitenancy
			return
		frappe.cache.set(key, "1")  # nosemgrep: frappe-cache-breaks-multitenancy
		frappe.log_error(
			title="passkeys: dormant — core serves passkeys natively",
			message=(
				"This site serves passkeys natively (frappe.passkey), so the passkeys "
				"app has gone dormant: every whitelisted endpoint now returns HTTP 417 "
				"PasskeyServedByCore and every hook is a no-op. The app is now safe to "
				"uninstall (bench --site <site> uninstall-app passkeys)."
			),
		)
	except Exception:
		pass


def _block_uninstall_lockout():
	# (a) password login disabled and no other core login method would survive
	# (the census mirrors core's validate_user_pass_login allowlist)
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


# ---------------------------------------------------------------------------
# User-form "Passkeys" section
# ---------------------------------------------------------------------------
# Programmatic Custom Fields rather than a fixture, because a core-native site must
# drop them. user_passkeys.js renders into the HTML field.


def sync_user_form_section():
	"""after_install + after_migrate: keep the section on the User form, or remove it
	when core serves passkeys natively."""
	if is_core_native():
		_remove_user_form_section()
	else:
		_create_user_form_section()


def _create_user_form_section():
	from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

	create_custom_fields(
		{
			"User": [
				{
					"fieldname": USER_FORM_SECTION_FIELD,
					"label": "Passkeys",
					"fieldtype": "Section Break",
					"insert_after": USER_FORM_ANCHOR,
					"collapsible": 1,
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
	"""Delete the section Custom Fields. Idempotent."""
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
# Uninstall drops the WebAuthn Credential + WebAuthn User Handle tables, so
# before_uninstall first writes both to one site-bound, HMAC-authenticated JSON file
# in the site's private files. import_credentials restores it after a reinstall
# (see docs/install.md).


def _exportable_fieldnames(doctype: str) -> list[str]:
	"""The stored fields of a doctype, from meta, so new fields travel automatically."""
	return [
		df.fieldname
		for df in frappe.get_meta(doctype).fields
		if df.fieldtype not in ("Section Break", "Column Break", "HTML")
	]


def export_credentials(path: str | None = None) -> str | None:
	"""Write every WebAuthn Credential + WebAuthn User Handle row to one signed JSON file
	(mode 0600, atomic) and return its path, or ``None`` when there is nothing to export.
	``path`` defaults to a timestamped file in the site's private files."""
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
	path = export_credentials()
	if path is None:
		return
	print(f"passkeys: credentials exported before uninstall -> {path}")
	print("passkeys: to restore them after reinstalling, run in `bench --site <site> console`:")
	print(f'passkeys:   from passkeys.install import import_credentials; import_credentials("{path}")')


def import_credentials(path: str, *, allow_existing: bool = False) -> dict:
	"""Restore a file written by :func:`export_credentials` after a reinstall and return
	a created / skipped / rejected summary.

	The destination must hold no passkey rows unless ``allow_existing=True`` (an
	operator-reviewed merge: identical rows are skipped, conflicting ones rejected).
	Console-only, but a crafted file must not bind a key to an account of its choosing,
	so a row is rejected when its user is missing or disabled, or when the user's handle
	disagrees with the site (or belongs to another user); every row for such a user is
	rejected. Credentials go in before handles so a passkey-only handle finds its
	enabled credential."""
	with open(path, encoding="utf-8") as fh:  # nosemgrep: frappe-security-file-traversal
		data = json.load(fh)
	_validate_export(data, path)
	if not allow_existing and (
		frappe.db.count("WebAuthn Credential") or frappe.db.count("WebAuthn User Handle")
	):
		frappe.throw(
			_(
				"Refusing to merge a credential export into live passkey data. Import into an empty installation, or pass allow_existing=True after reviewing conflicts."
			)
		)
	_refuse_passkey_only_without_login_mode(data)

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

	# A handle that differs from the user's live one, or that belongs to another user,
	# is a substitution attempt.
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

	frappe.db.commit()  # nosemgrep: frappe-manual-commit

	if summary["rejected"]:
		print(f"passkeys: import_credentials rejected {len(summary['rejected'])} row(s):")
		for line in summary["rejected"]:
			print(f"passkeys:   {line}")

	return summary


def _refuse_passkey_only_without_login_mode(data: dict) -> None:
	"""A passkey-only user restored while no passkey login mode is on would be locked
	out, and the handle's own validator would fail mid-restore; refuse up front."""
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


def _export_signature(payload: dict) -> str:
	unsigned = {key: value for key, value in payload.items() if key != "signature"}
	# Normalize Frappe value types first, then HMAC a deterministic byte form.
	normalized = json.loads(frappe.as_json(unsigned))
	message = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
	return hmac.new(_export_signing_key(), message, hashlib.sha256).hexdigest()


def _export_signing_key() -> bytes:
	key = frappe.conf.get("encryption_key")
	if not key:
		frappe.throw(_("This site has no encryption_key; a credential export cannot be authenticated."))
	return b"frappe-passkeys:credential-export:v2\x00" + str(key).encode()


def _validate_export(data, path: str) -> None:
	if not isinstance(data, dict) or data.get("schema") != CREDENTIAL_EXPORT_SCHEMA:
		frappe.throw(_("{0} is not a passkeys credential export.").format(path))
	if data.get("version") != CREDENTIAL_EXPORT_VERSION:
		frappe.throw(_("{0} uses an unsupported passkeys export version.").format(path))
	if data.get("site") != frappe.local.site:
		frappe.throw(_("{0} belongs to a different site.").format(path))
	signature = data.get("signature")
	if not isinstance(signature, dict) or signature.get("alg") != CREDENTIAL_EXPORT_SIGNATURE_ALG:
		frappe.throw(_("{0} has no supported export signature.").format(path))
	if not hmac.compare_digest(str(signature.get("value") or ""), _export_signature(data)):
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
	"""Whether a merge target equals the exported row on every field. Skipping on the
	identifier alone could keep a weaker sign counter, a different public key or a
	cleared passkey-only flag."""
	fields = _exportable_fieldnames(doctype)
	existing = frappe.db.get_value(doctype, name, fields, as_dict=True)
	if not existing:
		return False
	expected = {field: exported.get(field) for field in fields}
	return json.loads(frappe.as_json(existing)) == json.loads(frappe.as_json(expected))
