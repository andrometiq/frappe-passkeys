# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""The reference docs keep up with the code: every Passkey Settings field a user can set has a
row in docs/configuration.md, every typed wire error is in the error contract of
docs/rest-api.md, the risk-events table of docs/operations.md lists exactly the Activity Log
events the app writes, and docs/llms.txt links every page."""

import inspect
import re
from pathlib import Path

import frappe
from frappe.model import display_fieldtypes

from passkeys import errors, notifications, session
from passkeys.tests.compat import IntegrationTestCase

DOCS = Path(frappe.get_app_path("passkeys")).parent / "docs"
RELEASED_DOCS = "https://raw.githubusercontent.com/Andrometiq/frappe-passkeys/version-16/docs/"


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

	def test_risk_events_table_lists_every_activity_log_event(self):
		section = _section(DOCS / "operations.md", "## Monitoring the risk events")
		documented = {
			event
			for line in section.splitlines()
			if line.startswith("| `passkeys:")
			for event in re.findall(r"`(?:passkeys:)?(\w+)`", line.split("|")[1])
		}
		written = (
			{value for name, value in vars(notifications).items() if name.startswith("RISK_")}
			| set(re.findall(r'activity=\("(\w+)"', inspect.getsource(notifications)))
			| {f"grant_{event}" for event in re.findall(r'_audit_grant\("(\w+)"', inspect.getsource(session))}
		)
		self.assertTrue(written)
		self.assertEqual(
			sorted(documented),
			sorted(written),
			"operations.md risk-events table differs from the passkeys:<event> values the app writes",
		)

	def test_llms_txt_links_every_page_and_only_pages_that_exist(self):
		links = re.findall(r"\]\(([^)]+)\)", (DOCS / "llms.txt").read_text())
		self.assertTrue(links)
		self.assertEqual(
			[link for link in links if not link.startswith(RELEASED_DOCS)],
			[],
			f"llms.txt links that are not under {RELEASED_DOCS}",
		)
		linked = {link.removeprefix(RELEASED_DOCS) for link in links}
		self.assertEqual(
			sorted(page for page in linked if not (DOCS / page).is_file()),
			[],
			"llms.txt links to pages that are not in docs/",
		)
		pages = {page.name for page in DOCS.glob("*.md")} - {"README.md"}
		self.assertEqual(sorted(pages - linked), [], "docs/*.md pages missing from llms.txt")


def _section(path: Path, heading: str) -> str:
	"""One ``##`` section of a page, up to the next ``##`` heading."""
	text = path.read_text()
	begin = text.index(heading)
	end = text.find("\n## ", begin + len(heading))
	return text[begin : end if end != -1 else None]


def _bullet(path: Path, start: str) -> str:
	"""One top-level list item of a page, whitespace-collapsed."""
	text = path.read_text()
	begin = text.index(start)
	end = text.find("\n- ", begin + len(start))
	return " ".join(text[begin : end if end != -1 else None].split())
