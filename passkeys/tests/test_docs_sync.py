# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""The reference docs keep up with the code: every Passkey Settings field a user can set has a
row in docs/configuration.md, and every typed wire error is in the error contract of
docs/rest-api.md."""

import inspect
from pathlib import Path

import frappe
from frappe.model import display_fieldtypes

from passkeys import errors
from passkeys.tests.compat import IntegrationTestCase

DOCS = Path(frappe.get_app_path("passkeys")).parent / "docs"


class DocsSyncTest(IntegrationTestCase):
	def test_every_user_settable_setting_has_a_configuration_row(self):
		configuration = (DOCS / "configuration.md").read_text()
		fields = [
			field
			for field in frappe.get_meta("Passkey Settings").fields
			if field.fieldtype not in display_fieldtypes and not field.hidden and not field.read_only
		]
		self.assertTrue(fields)
		missing = [
			field.fieldname
			for field in fields
			if f"| **{field.label}** (`{field.fieldname}`) |" not in configuration
		]
		self.assertEqual(missing, [], "Passkey Settings fields without a `| **Label** (`fieldname`) |` row")

	def test_every_wire_error_is_in_the_rest_api_error_contract(self):
		contract = _bullet(DOCS / "rest-api.md", "- **Typed errors**:")
		wire_errors = [
			error
			for _name, error in inspect.getmembers(errors, inspect.isclass)
			if issubclass(error, Exception) and error.__module__ == errors.__name__
		]
		self.assertTrue(wire_errors)
		missing = [
			f"{error.__name__} ({error.http_status_code})"
			for error in wire_errors
			if f"`{error.__name__}` ({error.http_status_code}" not in contract
		]
		self.assertEqual(
			missing, [], "passkeys.errors classes missing from the rest-api.md Typed errors list"
		)


def _bullet(path: Path, start: str) -> str:
	"""One top-level list item of a page, whitespace-collapsed."""
	text = path.read_text()
	begin = text.index(start)
	end = text.find("\n- ", begin + len(start))
	return " ".join(text[begin : end if end != -1 else None].split())
