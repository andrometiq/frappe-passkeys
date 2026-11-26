# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""The translation template keeps up with the client bundles: Frappe's generate-pot-file sends
``passkeys/public/js`` through the app's extractor, which reads ``__()``, ``t()``, ``tr()`` and
``N_()``, and every string it finds is in ``passkeys/locale/main.pot``."""

import io
import re
from pathlib import Path

import frappe
from babel.messages.pofile import read_po
from babel.util import pathmatch
from frappe.gettext.translate import get_method_map

from passkeys import translation_extractor
from passkeys.tests.compat import IntegrationTestCase

APP = Path(frappe.get_app_path("passkeys"))
REGENERATE = (
	"Regenerate it from the bench root with `bench generate-pot-file --app passkeys`, or, when the "
	"bench links apps/passkeys to a checkout elsewhere, `env/bin/python apps/passkeys/scripts/generate_pot.py`"
	" (CONTRIBUTING.md, Translations)."
)


def _extract(fileobj):
	return [
		(function, message)
		for _lineno, function, message, _comments in translation_extractor.extract(fileobj, (), (), {})
	]


def _bundle_messages():
	"""``{msgid: "file:line"}`` for every string the extractor finds in the bundles."""
	messages = {}
	for path in sorted((APP / "public" / "js").glob("*.js")):
		with path.open("rb") as fileobj:
			for lineno, _function, message, _comments in translation_extractor.extract(fileobj, (), (), {}):
				msgid = message[1] if isinstance(message, tuple) else message
				messages.setdefault(msgid, f"{path.name}:{lineno}")
	return messages


class TranslationTemplateTest(IntegrationTestCase):
	def test_bundles_go_through_the_app_extractor(self):
		bundle = "passkeys/public/js/passkey_login.bundle.js"
		methods = [method for pattern, method in get_method_map("passkeys") if pathmatch(pattern, bundle)]
		self.assertEqual(methods[:1], ["passkeys.translation_extractor.extract"])

	def test_extractor_reads_each_translation_name(self):
		code = b'__("a"); t("b"); tr("c {0}", [x]); var COPY = { d: N_("d " + "e") }; __("f", null, "ctx"); go("g");'
		self.assertEqual(
			_extract(io.BytesIO(code)),
			[
				("gettext", "a"),
				("gettext", "b"),
				("gettext", "c {0}"),
				("gettext", "d e"),
				("pgettext", ("ctx", "f")),
			],
		)

	def test_template_has_every_bundle_string(self):
		messages = _bundle_messages()
		self.assertTrue(messages)
		with (APP / "locale" / "main.pot").open("rb") as fileobj:
			template = {message.id for message in read_po(fileobj) if message.id}
		missing = sorted(f"{where}: {text}" for text, where in messages.items() if text not in template)
		self.assertEqual(missing, [], f"Bundle strings missing from passkeys/locale/main.pot. {REGENERATE}")

	def test_no_bundle_translates_a_code(self):
		codes = sorted(
			f"{where}: {text}"
			for text, where in _bundle_messages().items()
			if re.fullmatch(r"[a-z0-9_.]+", text)
		)
		self.assertEqual(codes, [], "Translated strings that look like codes, not screen text")
