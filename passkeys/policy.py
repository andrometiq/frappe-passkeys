# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RP ID / origin policy and the UV / sign-count / BE-BS matrices (folds into
``frappe/passkey.py``). RP/origin validation happens at settings-save time from pinned
configuration, never on a guest-request path and never from ``Host``/``X-Forwarded-*``
headers."""

import importlib.util
import re
import subprocess
import sys
from urllib.parse import urlsplit

import frappe
from frappe import _
from frappe.utils import cint

LOCALHOST_HOSTS = ("localhost", "127.0.0.1")
WEBAUTHN_IMPORT_TIMEOUT = 30
WEBAUTHN_IMPORT_STDERR_LIMIT = 4096


def webauthn_available() -> bool:
	return importlib.util.find_spec("webauthn") is not None


def validate_webauthn_importable() -> None:
	"""Refuse enablement unless the full ceremony engine imports, in a child process so
	crypto never loads into the serving worker."""
	try:
		result = subprocess.run(
			[sys.executable, "-c", "import passkeys.engine"],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE,
			check=False,
			timeout=WEBAUTHN_IMPORT_TIMEOUT,
		)
	except subprocess.TimeoutExpired as exc:
		_raise_webauthn_import_error(
			_("the dependency check timed out after {0} seconds").format(WEBAUTHN_IMPORT_TIMEOUT),
			exc.stderr,
		)
	except OSError as exc:
		_raise_webauthn_import_error(_("the Python child process could not start: {0}").format(str(exc)))
	if result.returncode:
		_raise_webauthn_import_error(
			_("the dependency check exited with status {0}").format(result.returncode), result.stderr
		)


def _raise_webauthn_import_error(reason: str, stderr=None) -> None:
	detail = _stderr_tail(stderr)
	message = _(
		"Cannot enable passkeys because the WebAuthn dependencies could not be imported: {0}."
	).format(reason)
	if detail:
		message += " " + _("Error output: {0}").format(detail)
	frappe.throw(message)


def _stderr_tail(stderr: bytes | None) -> str:
	return (stderr or b"")[-WEBAUTHN_IMPORT_STDERR_LIMIT:].decode("utf-8", errors="replace").strip()


def resolve_rp_id(settings) -> str | None:
	"""Explicit ``passkey_rp_id``, else the exact host of the site's ``host_name`` —
	never a derived parent domain; widening is an explicit admin setting."""
	explicit = (settings.get("passkey_rp_id") or "").strip().lower()
	if explicit:
		validate_rp_id_shape(explicit)
		return explicit

	host_name = (frappe.conf.get("host_name") or "").strip()
	if not host_name:
		return None
	if "//" not in host_name:
		host_name = "//" + host_name
	host = urlsplit(host_name).hostname
	return host.lower() if host else None


def validate_rp_id_shape(rp_id: str) -> None:
	if not rp_id or rp_id.startswith(".") or any(c in rp_id for c in ("/", ":", " ", "@", "?", "#")):
		frappe.throw(
			_("Passkey RP ID must be a bare host name without scheme, port or path: {0}").format(rp_id)
		)


def is_in_rp_scope(host: str, rp_id: str) -> bool:
	return host == rp_id or host.endswith("." + rp_id)


def resolve_origins(settings, rp_id: str) -> list[str]:
	"""The exact trusted web origins: ``host_name``'s origin when it is inside ``rp_id``,
	plus the explicitly listed ones. An RP ID is a credential scope, never an origin."""
	configured = resolve_site_origin(rp_id)
	origins = [configured] if configured else []
	for line in (settings.get("passkey_origins") or "").splitlines():
		line = line.strip()
		canonical = canonical_web_origin(line) if line else None
		origin = canonical or line
		if origin and origin not in origins:
			origins.append(origin)
	return origins


def canonical_web_origin(raw: str) -> str | None:
	"""The browser-canonical ``scheme://host[:port]`` form (lower case, default port
	dropped, as in ``clientDataJSON.origin``), or ``None``."""
	raw = (raw or "").strip()
	if not raw:
		return None
	parts = urlsplit(raw)
	if (
		parts.scheme.lower() not in ("http", "https")
		or not parts.hostname
		or parts.username
		or parts.password
		or parts.path
		or parts.query
		or parts.fragment
		or any(char.isspace() for char in parts.hostname)
	):
		return None
	try:
		port = parts.port
		host = parts.hostname.encode("idna").decode("ascii").lower()
	except (UnicodeError, ValueError):
		return None
	scheme = parts.scheme.lower()
	if port == (443 if scheme == "https" else 80):
		port = None
	return f"{scheme}://{host}{f':{port}' if port else ''}"


def configured_site_origin() -> str | None:
	"""The origin of the trusted ``host_name`` setting."""
	raw = (frappe.conf.get("host_name") or "").strip()
	if not raw:
		return None
	if "//" not in raw:
		raw = "https://" + raw
	return canonical_web_origin(raw)


def resolve_site_origin(rp_id: str) -> str | None:
	"""``host_name``'s origin, only when it falls within the RP scope."""
	configured = configured_site_origin()
	if not configured:
		return None
	return configured if is_in_rp_scope(urlsplit(configured).hostname or "", rp_id) else None


def validate_origins(settings, rp_id: str | None) -> None:
	"""Save-time shape/HTTPS validation, plus RP scope when one resolves."""
	configured = [line.strip() for line in (settings.get("passkey_origins") or "").splitlines()]
	origins = resolve_origins(settings, rp_id) if rp_id else [origin for origin in configured if origin]
	if rp_id and not origins:
		frappe.throw(
			_(
				"Configure at least one exact passkey origin or set this site's host_name within the RP ID scope."
			)
		)
	for origin in origins:
		canonical = canonical_web_origin(origin)
		if not canonical:
			frappe.throw(
				_("Invalid passkey origin {0}: expected scheme://host[:port], one per line").format(origin)
			)
		parts = urlsplit(canonical)
		host = (parts.hostname or "").lower()
		if parts.scheme != "https":
			if not (parts.scheme == "http" and _is_dev_localhost(host)):
				frappe.throw(
					_(
						"Passkey origin {0} must use HTTPS (http is allowed only for localhost while developer mode is on)"
					).format(origin)
				)
		if rp_id and not is_in_rp_scope(host, rp_id):
			frappe.throw(
				_(
					"Origin {0} cannot use RP ID {1}: its host must equal the RP ID or be a subdomain of it. Serving multiple unrelated domains requires Related Origin Requests, which is deferred."
				).format(origin, rp_id)
			)


def _is_dev_localhost(host: str) -> bool:
	return bool(frappe.conf.get("developer_mode")) and host in LOCALHOST_HOSTS


def lock_system_setting(fieldname: str) -> int:
	"""Lock one System Settings field and return its latest committed integer value (a
	plain read can return the transaction's stale snapshot). The floor validators take the
	Passkey Settings lock first, then these rows."""
	rows = frappe.db.sql(
		"""select `value` from `tabSingles`
		where `doctype` = %s and `field` = %s
		for update""",
		("System Settings", fieldname),
	)
	return cint(rows[0][0] if rows else 0)


# A native Android app asserts ``android:apk-key-hash:<base64url SHA-256 of the signing
# cert>``. These Trusted App Origins join the engine's ``expected_origin`` list but never
# the web-origin checks. iOS asserts ``https://<rp_id>``, a web origin.
_APK_KEY_HASH_PREFIX = "android:apk-key-hash:"
# SHA-256 is 32 bytes → 43 unpadded base64url characters.
_APK_KEY_HASH_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def app_origins(settings) -> list[str]:
	"""The configured Trusted App Origins, trimmed and de-duplicated."""
	origins: list[str] = []
	for line in (settings.get("passkey_app_origins") or "").splitlines():
		line = line.strip()
		if line and line not in origins:
			origins.append(line)
	return origins


def resolve_expected_origins(settings, rp_id: str) -> list[str]:
	"""The engine's ``expected_origin`` allowlist: the web origins plus the Trusted App
	Origins."""
	origins = resolve_origins(settings, rp_id)
	for origin in app_origins(settings):
		if origin not in origins:
			origins.append(origin)
	return origins


def validate_app_origins(settings) -> None:
	"""Save-time shape check: each line is ``android:apk-key-hash:<hash>``, the unpadded
	base64url SHA-256 of Google's Play app-signing certificate (not the upload key)."""
	for line in (settings.get("passkey_app_origins") or "").splitlines():
		origin = line.strip()
		if not origin:
			continue
		if not origin.startswith(_APK_KEY_HASH_PREFIX):
			frappe.throw(
				_(
					"Invalid Trusted App Origin {0}: only android:apk-key-hash:<hash> entries are supported. iOS needs no entry here; configure its https://<RP ID> value under Passkey Origins."
				).format(origin)
			)
		digest = origin[len(_APK_KEY_HASH_PREFIX) :]
		if not _APK_KEY_HASH_RE.match(digest):
			frappe.throw(
				_(
					"Invalid Trusted App Origin {0}: the hash must be an unpadded base64url SHA-256 of the app-signing certificate (43 characters from A-Z a-z 0-9 - _). Use Google's Play app-signing certificate, not the upload key."
				).format(origin)
			)


# Wire ``userVerification`` per assertion ceremony. Advisory only: each ceremony enforces
# UV on the verified result, never on the wire string.
UV_WIRE = {
	"first_factor": "preferred",
	"second_factor": "discouraged",
	"confirmation": "required",
}

# First-factor UV enforcement outcomes.
UV_SESSION = "session"  # UV=1 ∧ uv_initialized=1 → passwordless session
UV_SETUP = "uv_setup"  # UV=1 ∧ uv_initialized=0 → inline step-up
UV_REJECT = "reject"  # UV=0 → a UV-less assertion never yields a passwordless session


def passwordless_uv_outcome(uv_bit: bool, uv_initialized: bool) -> str:
	"""First-factor gate: passwordless needs UV=1 AND ``uv_initialized`` (L3 §4 — the
	false→true flip needs a second factor)."""
	if not uv_bit:
		return UV_REJECT
	return UV_SESSION if uv_initialized else UV_SETUP


def resident_key_for_flow(flow: str) -> str:
	"""``required`` for an explicit add (a discoverable first factor), ``preferred`` for
	conditional create."""
	return "required" if flow == "explicit" else "preferred"


# Sign-count policy, app-side (the library's own hard-reject is disabled).

SIGN_COUNT_UNCHANGED = "unchanged"  # 0→0 (counter-less / synced authenticator) — pass, store 0
SIGN_COUNT_INCREMENT = "increment"  # new > stored — pass, store new
SIGN_COUNT_REPLAY = "replay"  # new == stored ≠ 0 — ALWAYS reject (not knob-controlled)
SIGN_COUNT_REGRESSION = "regression"  # new < stored — log+flag; reject iff hard-fail knob on


def classify_sign_count(stored: int, asserted: int) -> str:
	"""Classify an asserted counter against the stored one."""
	stored, asserted = int(stored), int(asserted)
	if asserted == 0 and stored == 0:
		return SIGN_COUNT_UNCHANGED
	if asserted > stored:
		return SIGN_COUNT_INCREMENT
	if asserted == stored:  # nonzero equal
		return SIGN_COUNT_REPLAY
	return SIGN_COUNT_REGRESSION  # asserted < stored (incl. asserted 0 while stored > 0)


def sign_count_to_store(stored: int, asserted: int) -> int:
	"""Upward-only: never write the stored counter downward."""
	return int(asserted) if classify_sign_count(stored, asserted) == SIGN_COUNT_INCREMENT else int(stored)


def backup_eligibility_mutated(stored_be: bool, asserted_be: bool) -> bool:
	"""BE is write-once at registration; a changed BE is a clone/forgery signal
	(stricter than spec; the library checks only BS-without-BE)."""
	return bool(stored_be) != bool(asserted_be)
