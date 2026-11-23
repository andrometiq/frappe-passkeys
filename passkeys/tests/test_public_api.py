# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RELEASES.md's public-API promise as checks: every name in public_api.json still works, every name
the pages RELEASES.md links to call public is in it, and a release's middle number matches it."""

import importlib
import inspect
import json
import re
from pathlib import Path

import frappe

import passkeys
from passkeys import errors
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.test_docs_sync import DOCS, _bullet

APP = Path(passkeys.__file__).parent
SNAPSHOT = APP / "tests" / "public_api.json"
CALLABLE_SECTIONS = ("endpoints", "decorator")
RETIRE_HINT = (
	'RELEASES.md: keep the old name working. To retire it, list it under "deprecated" first; a later '
	'release removes it, raises "middle" in passkeys/tests/public_api.json and says so in the '
	"changelog's Upgrade notes."
)


class PublicApiTest(IntegrationTestCase):
	def setUp(self):
		self.snapshot = json.loads(SNAPSHOT.read_text())

	def test_every_snapshot_name_still_works(self):
		self.assertEqual(get_missing(self.snapshot), [], f"Public API removed or renamed. {RETIRE_HINT}")

	def test_every_documented_name_is_in_the_snapshot(self):
		new = [
			name
			for section, names in get_documented_api().items()
			for name in sorted(names)
			if name not in self.snapshot[section]
		]
		new += [
			f"{path}({parameter})"
			for section in CALLABLE_SECTIONS
			for path, args in self.snapshot[section].items()
			if (function := get_function(path))
			for parameter in inspect.signature(function).parameters
			if parameter not in args
		]
		self.assertEqual(new, [], "New public API: add it to passkeys/tests/public_api.json.")

	def test_a_release_version_carries_the_snapshot_middle_number(self):
		version = re.fullmatch(r"\d+\.(\d+)\.\d+(-dev)?", passkeys.__version__)
		self.assertIsNotNone(
			version, f"passkeys.__version__ {passkeys.__version__!r} is not X.Y.Z or X.Y.Z-dev"
		)
		if version[2]:
			self.skipTest("a -dev version has no release line; a release commit sets X.Y.Z")
		self.assertEqual(
			int(version[1]),
			self.snapshot["middle"],
			f'passkeys.__version__ {passkeys.__version__} and "middle" in passkeys/tests/public_api.json '
			"disagree. RELEASES.md: the middle number goes up only when a release removes or renames "
			"public API; raise both together.",
		)


def get_missing(snapshot: dict) -> list[str]:
	"""Snapshot names the code no longer provides."""
	checks = get_presence_checks()
	missing = [name for section, check in checks.items() for name in snapshot[section] if not check(name)]
	for section in CALLABLE_SECTIONS:
		for path, args in snapshot[section].items():
			function = get_function(path)
			if function is None or (section == "endpoints" and function not in frappe.whitelisted):
				missing.append(path)
				continue
			parameters = inspect.signature(function).parameters
			missing += [f"{path}({arg})" for arg in args if arg not in parameters]
	return missing


def get_presence_checks() -> dict:
	"""Snapshot section → whether one of its names still exists in the code."""
	# Tests included: two Activity Log events are composed from a prefix (session._audit_grant) and
	# pinned by test_confirm_api rather than written out in the code.
	python = read_all(APP, "*.py")
	javascript = read_all(APP / "public" / "js", "*.js")
	assets = javascript + read_all(APP / "public" / "css", "*.css")
	fields = {field.fieldname for field in frappe.get_meta("Passkey Settings").fields}
	return {
		"errors": lambda name: inspect.isclass(getattr(errors, name, None)),
		"settings_fields": lambda name: name in fields,
		"activity_events": lambda name: has_word(python, name.removeprefix("passkeys:")),
		"js_globals": lambda name: bool(
			re.search(rf"\.{re.escape(name.removeprefix('frappe.'))}\s*=(?!=)", javascript)
		),
		"css_hooks": lambda name: has_word(assets, name[1:]),
		"well_known": is_served,
	}


def is_served(path: str) -> bool:
	"""The reverse proxy maps a well-known path onto the guest GET endpoint named after it
	(docs/mobile-apps.md); Frappe itself routes no app ``/.well-known/`` path."""
	function = get_function(f"passkeys.well_known.{Path(path).stem.replace('-', '_')}")
	return (
		function in frappe.guest_methods
		and "GET" in frappe.allowed_http_methods_for_whitelisted_func[function]
	)


def get_documented_api() -> dict[str, set[str]]:
	"""What the pages RELEASES.md §Public API links to name as public, by snapshot section."""
	rest_api = (DOCS / "rest-api.md").read_text()
	admin = get_section(DOCS / "rest-api.md", "## System Manager")
	admin_module = re.search(r"under\s+`(passkeys\.[\w.]+)`", admin)[1]
	events = get_section(DOCS / "operations.md", "## Monitoring the risk events", end="\n#")
	return {
		"endpoints": set(re.findall(r"^(?:### |- \*\*)`(passkeys\.[\w.]+)`", rest_api, re.M))
		| {f"{admin_module}.{name}" for name in re.findall(r"^(?:### |- )`(\w+)`", admin, re.M)},
		"decorator": {"passkeys.confirm.passkey_protected"},
		"errors": set(re.findall(r"`(\w+)` \(\d{3}", _bullet(DOCS / "rest-api.md", "- **Typed errors**:"))),
		"settings_fields": set(
			re.findall(r"^\| \*\*.+?\*\* \(`(\w+)`\) \|", (DOCS / "configuration.md").read_text(), re.M)
		),
		"activity_events": {
			"passkeys:" + name.removeprefix("passkeys:")
			for row in re.findall(r"^\| (`passkeys:[^|]*)\|", events, re.M)
			for name in re.findall(r"`([\w:]+)`", row)
		},
		"js_globals": get_js_globals(
			get_section(DOCS / "custom-ui.md", "## The public JavaScript surface", end="\n#")
		),
		"css_hooks": get_css_hooks(get_section(DOCS / "custom-ui.md", "## Semantic markup contract")),
		"well_known": set(re.findall(r"/\.well-known/[\w.-]+", (DOCS / "mobile-apps.md").read_text())),
	}


def get_js_globals(section: str) -> set[str]:
	"""`frappe.*` names; a `.name` span after one names a sibling (`frappe.ui.passkey.headless` / `.call`)."""
	names, parent = set(), ""
	for span in re.findall(r"`([^`]+)`", section):
		name = span.split("(")[0]
		if re.fullmatch(r"frappe(\.\w+)+", name):
			names.add(name)
			parent = name.rpartition(".")[0]
		elif parent and re.fullmatch(r"\.\w+", name):
			names.add(parent + name)
	return names


def get_css_hooks(section: str) -> set[str]:
	"""`.class` / `#id` hooks; a `--modifier` or `__part` span extends the hook before it."""
	hooks, last = set(), ""
	for span in re.findall(r"`([^`]+)`", section):
		if re.match(r"[.#][a-z]", span):
			found = re.findall(r"[.#][a-z][\w-]*", span)
			hooks.update(found)
			last = found[-1]
		elif last and re.fullmatch(r"(--|__)\w+", span):
			hooks.add(last + span)
	return hooks


def get_section(path: Path, heading: str, end: str = "\n## ") -> str:
	"""A page's text from ``heading`` up to the next ``end`` (by default the next same-level heading)."""
	text = path.read_text()
	begin = text.index(heading)
	stop = text.find(end, begin + len(heading))
	return text[begin : stop if stop != -1 else None]


def get_function(path: str):
	"""The function at a dotted path, or None when its module or name is gone."""
	module_name, _, name = path.rpartition(".")
	try:
		return getattr(importlib.import_module(module_name), name, None)
	except ModuleNotFoundError:
		return None


def read_all(folder: Path, pattern: str) -> str:
	return "\n".join(path.read_text() for path in sorted(folder.rglob(pattern)))


def has_word(text: str, word: str) -> bool:
	return bool(re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", text))
