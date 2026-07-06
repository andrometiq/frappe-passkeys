# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""AAGUID → provider display name (DESIGN-v1 §8.2, §2.1).

Backed by the vendored community snapshot ``public/aaguid-map.json`` (the
``passkey-authenticator-aaguids`` combined list, MIT — provenance + refresh
steps in ``docs/aaguid-map.md``). The same file is served to the client at
``/assets/passkeys/aaguid-map.json``, so server and browser resolve from one
snapshot.

Display/telemetry only, never policy (§2.1): an AAGUID is authenticator-
asserted and unverified under ``attestation="none"``. Zero / empty / unknown
AAGUIDs are normal (§8.2 — Safari ships all-zeros), so ``provider_name``
answers ``None`` and callers fall back to a generic label; an unreadable or
empty snapshot degrades the same way (§2.3 "tolerant of empty payloads").

Deliberately frappe-free and ``webauthn``-free (§1.3 import discipline —
importable from any hook path); the file is read once per process
(``lru_cache``).
"""

import json
from functools import lru_cache
from pathlib import Path

ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"

_MAP_PATH = Path(__file__).parent / "public" / "aaguid-map.json"


@lru_cache(maxsize=1)
def _load_map() -> dict:
	"""Parse the vendored snapshot into ``{lowercase aaguid: name}``. Tolerant
	of every degraded shape: missing/unreadable/non-object file ⇒ ``{}``;
	the ``_meta`` provenance key and non-string values are skipped; upstream's
	``{"name": ...}`` object form is accepted alongside plain strings (the same
	tolerance the client's ``providerFor`` has)."""
	try:
		raw = json.loads(_MAP_PATH.read_text())
	except (OSError, ValueError):
		return {}
	if not isinstance(raw, dict):
		return {}
	out = {}
	for key, value in raw.items():
		if not isinstance(key, str) or key.startswith("_"):
			continue  # _meta provenance block, never a lookup row
		if isinstance(value, dict):
			value = value.get("name")
		if isinstance(value, str) and value.strip():
			out[key.lower()] = value.strip()
	return out


def provider_name(aaguid: str | None) -> str | None:
	"""The human provider name for an AAGUID (e.g. ``"Apple Passwords"``), or
	``None`` for zero/empty/unknown — the caller's cue for its generic
	fallback ("Unknown provider" on cards, the neutral default label at
	registration). Case-insensitive: the column stores whatever the
	authenticator asserted; the snapshot keys are lowercase."""
	if not aaguid:
		return None
	needle = str(aaguid).strip().lower()
	if not needle or needle == ZERO_AAGUID:
		return None
	return _load_map().get(needle)
