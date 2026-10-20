"""Shared raw scopes for class cleanup and the committed-state suite guard."""

import json
import sys

import frappe

SETTINGS_SCOPES = {
	"Passkey Settings": ("Singles", {"doctype": "Passkey Settings"}),
	"System Settings": ("Singles", {"doctype": "System Settings"}),
	"System defaults": ("DefaultValue", {"parent": "__default"}),
	"Passkey Enforcement Role": (
		"Passkey Enforcement Role",
		{"parent": "Passkey Settings", "parenttype": "Passkey Settings"},
	),
}
FIXTURE_SCOPES = {
	"WebAuthn Credential": ("WebAuthn Credential", {}),
	"WebAuthn User Handle": ("WebAuthn User Handle", {}),
	"User": ("User", {"name": ["like", "passkey-test-%"]}),
	"DefaultValue": ("DefaultValue", {"parent": ["in", ["__passkeys", "__2fa"]]}),
	"Role": ("Role", {"name": "Passkey 2FA Test Role"}),
}


def capture():
	return {
		label: frappe.db.get_values(
			doctype, filters, "*", as_dict=True, order_by="field" if doctype == "Singles" else "name"
		)
		for label, (doctype, filters) in (SETTINGS_SCOPES | FIXTURE_SCOPES).items()
	}


def serialized(rows):
	return sorted(json.dumps(row, sort_keys=True, default=str) for row in rows)


def restore_rows(doctype, filters, rows):
	"""Restore complete raw rows without document validation or save side effects."""
	frappe.db.delete(doctype, filters)
	for row in rows:
		columns = ", ".join(f"`{column}`" for column in row)
		placeholders = ", ".join(["%s"] * len(row))
		frappe.db.sql(f"insert into `tab{doctype}` ({columns}) values ({placeholders})", tuple(row.values()))


def delete_fixture(doctype, name, **kwargs):
	"""Core User cascades do not inherit delete_permanently."""
	if doctype == "User":
		frappe.delete_doc("Notification Settings", name, ignore_permissions=True, delete_permanently=True)
		for child in ("Custom Sidebar", "Dock"):
			if frappe.db.exists("DocType", child):
				for child_name in frappe.get_all(child, filters={"user": name}, pluck="name"):
					frappe.delete_doc(
						child, child_name, force=1, ignore_permissions=True, delete_permanently=True
					)
	frappe.delete_doc(doctype, name, **{**kwargs, "delete_permanently": True})


def restore(baseline, owner):
	changes = []
	try:
		frappe.db.rollback()
		current = capture()
		for label, (doctype, _) in FIXTURE_SCOPES.items():
			original_names = {row.name for row in baseline[label]}
			added = [row.name for row in current[label] if row.name not in original_names]
			for name in added:
				if doctype in {"User", "Role"}:
					delete_fixture(doctype, name, force=1, ignore_permissions=True)
				else:
					frappe.db.delete(doctype, {"name": name})
			if added:
				changes.append(f"deleted {len(added)} {label}")
		current = capture()
		for label, (doctype, filters) in SETTINGS_SCOPES.items():
			if serialized(current[label]) != serialized(baseline[label]):
				restore_rows(doctype, filters, baseline[label])
				changes.append(f"restored {label}")
		frappe.db.commit()
		if changes:
			print(f"committed-state cleanup {owner}: {'; '.join(changes)}", file=sys.stderr)
	except Exception:
		frappe.db.rollback()
		raise
	finally:
		frappe.clear_cache()


def snapshot():
	"""Print stable full rows from a fresh bench-execute connection."""
	for label, rows in sorted(capture().items()):
		for row in serialized(rows):
			print(json.dumps(label) + " " + row)
