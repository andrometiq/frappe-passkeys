# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Fold the legacy ``passkey_enrollment_nudge`` Check into the new
``passkey_enrollment_policy`` Select — the rung control of the passkey adoption /
enforcement ladder — and seed the break-glass System Manager exempt role.

Behaviour-preserving mapping for sites that predate the ladder::

    passkey_enrollment_nudge = 1   ->  passkey_enrollment_policy = "Nudge"
    passkey_enrollment_nudge = 0   ->  passkey_enrollment_policy = "Off"
    (unset / brand-new install)    ->  leave the field default ("Nudge")

Single DocType values live in ``tabSingles`` (key/value rows), so the old
``passkey_enrollment_nudge`` value survives the schema sync that drops its DocField
and is still readable here in ``post_model_sync`` — read straight from the ``Singles``
table (``get_single_value`` would reject the now-absent field). The patch is
idempotent: it only folds when the new policy has no explicit value yet, and never
clobbers a policy an administrator has already chosen."""

import frappe
from frappe.utils import cint

from passkeys import install

# The enforcement scalar defaults an upgraded (existing) settings row never received
# — after_install seeds these on a fresh install, but a migrate does not touch a
# populated Single. Persist them directly (no doc.save ⇒ no validate, so a site with a
# login mode already on cannot break the patch), only where still unset.
_ENFORCEMENT_DEFAULTS = {
	"passkey_enforce_scope": "All Users",
	"passkey_enforce_grace_logins": 3,
	"passkey_enforce_incapable": "Degrade to Nudge",
	"passkey_enforce_allow_hybrid": 1,
}


def execute():
	if install.is_core_native():
		return  # dormant shell: core owns Passkey Settings — nothing to migrate

	# Fold only when the new field has no explicit value yet — idempotent and never
	# overwrites a policy an admin already set.
	current = frappe.db.get_single_value("Passkey Settings", "passkey_enrollment_policy")
	if not current:
		# Read the orphaned value directly from tabSingles — the DocField is gone, so
		# get_single_value would reject it as an unknown column.
		legacy = frappe.db.get_value(
			"Singles",
			{"doctype": "Passkey Settings", "field": "passkey_enrollment_nudge"},
			"value",
			order_by=None,  # tabSingles has no `creation` column to order by
		)
		# legacy is None on a brand-new install (the field default "Nudge" already
		# applies); "0"/"1" on an upgrade from the old Check.
		if legacy is not None:
			frappe.db.set_single_value(
				"Passkey Settings",
				"passkey_enrollment_policy",
				"Nudge" if cint(legacy) else "Off",
			)

	# Drop the orphaned legacy Singles row so it can never mask the new field.
	frappe.db.delete("Singles", {"doctype": "Passkey Settings", "field": "passkey_enrollment_nudge"})

	# Persist the enforcement scalar defaults an upgraded row never received. Test the
	# raw Singles row (not get_single_value — it casts a missing Int to 0, which is
	# indistinguishable from an explicit 0) so an admin's real choice is never clobbered.
	for field, default in _ENFORCEMENT_DEFAULTS.items():
		stored = frappe.db.get_value(
			"Singles", {"doctype": "Passkey Settings", "field": field}, "value", order_by=None
		)
		if stored is None:
			frappe.db.set_single_value("Passkey Settings", field, default)

	# Seed the break-glass System Manager exempt role for upgraded sites (fresh
	# installs get it via install.after_install -> ensure_enforcement_defaults()).
	install.ensure_enforcement_defaults()
