# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Regenerate passkeys/locale/main.pot with Frappe's own generate_pot, on a bench whose
environment imports the app from a checkout outside the bench (a linked apps/passkeys).

Frappe's hooks.py extractor imports hooks.py by its path relative to the bench; this imports it
relative to the checkout instead. Run from the bench root with the
bench's Python (see CONTRIBUTING.md, Translations)."""

import importlib
from pathlib import Path

import frappe
from frappe.gettext import translate

# A maintainer script the app never imports: it swaps the extractor's module loader in its own process only.
from frappe.gettext.extractors import navbar  # nosemgrep: frappe-monkey-patching-not-allowed


def get_module(path):
	checkout = Path(frappe.get_app_path("passkeys")).resolve().parent
	return importlib.import_module(".".join(Path(path).resolve().relative_to(checkout).with_suffix("").parts))


if __name__ == "__main__":
	frappe.init(site="", sites_path="sites")
	navbar.get_module = get_module
	translate.generate_pot("passkeys")
