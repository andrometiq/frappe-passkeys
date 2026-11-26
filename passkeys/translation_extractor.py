# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Translation-template extractor for ``passkeys/public/js`` (wired in ``babel_extractors.csv``).

Frappe's JavaScript extractor reads only literal ``__()`` calls. The bundles also translate
through passkeys_common's ``t()`` and an injected ``tr()``, and mark table text with ``N_()``,
which returns it untranslated for the renderer to translate when it is shown."""

from frappe.gettext.extractors.javascript import extract_javascript

KEYWORDS = ("__", "t", "tr", "N_")


def extract(fileobj, keywords, comment_tags, options):
	"""Babel extractor: Frappe's JavaScript extraction with this app's translation names."""
	code = fileobj.read().decode("utf-8")
	for lineno, _function, messages in extract_javascript(code, keywords=KEYWORDS, options=options):
		if not messages or not messages[0]:
			continue
		if isinstance(messages, tuple):
			if len(messages) == 3 and messages[2]:
				yield lineno, "pgettext", (messages[2], messages[0]), []
				continue
			messages = messages[0]
		yield lineno, "gettext", messages, []
