# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Sanctioned-hook enforcement seams (DESIGN-v1 §6.1; folds into ``frappe``'s
own auth surface on the core merge).

**Hook-path import discipline (§1.3):** ``guard_system_settings`` rides
``doc_events`` on System Settings ``validate`` — a hook that fires on every
System Settings save — so this module MUST NOT import ``webauthn`` (directly or
transitively). It imports only ``frappe``.

The ``on_login`` veto (``passkey_only_login``, §9.3) and the sudo-window seed
(§7.1, currently in ``session.py``) are the other tenants of this module in the
core-merge layout; only the two-way 2FA-floor guard is built here (§6.1)."""

import frappe
from frappe import _
from frappe.utils import cint


def guard_system_settings(doc, method=None):
	"""System Settings ``validate``: the reverse half of the two-way 2FA floor
	(§6.1 / B-F7). The Passkey Settings validator refuses enabling
	``passkey_as_second_factor`` while core ``enable_two_factor_auth`` is off;
	this guard refuses the *other* direction — flipping ``enable_two_factor_auth``
	**1 → 0** while ``passkey_as_second_factor`` is on — which would otherwise
	silently evaporate the structural backstop (direct-POST users would then walk
	through ``login()`` with a password alone while the passkey-2FA UI keeps
	working, and nobody would notice).

	Only the genuine 1→0 transition is blocked: an already-off value staying off
	cannot make the floor any weaker, and blocking every save on an
	already-desynced site (a raw ``db_set``/console edit — §14 console-bypass
	posture) would deadlock System Settings entirely. The runtime desync that a
	console edit can still create is surfaced by the leg-1 daily observation log
	(``passkeys.passkey`` — §6.1c)."""
	new_value = cint(doc.enable_two_factor_auth)
	if new_value:
		return  # staying on / turning on — nothing to guard
	old_value = cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth"))
	if not old_value:
		return  # already off (or a console-created desync) — not a 1→0 flip
	if not cint(frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor")):
		return  # passkey second factor not in use — no floor to protect
	frappe.throw(
		_(
			"Cannot disable Two Factor Authentication: it is the structural backstop for "
			"Passkey as Second Factor (direct password logins that bypass the passkey UI "
			"would otherwise face no second factor). Disable 'Passkey as Second Factor' in "
			"Passkey Settings first."
		),
		frappe.ValidationError,
	)
