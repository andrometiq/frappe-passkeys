# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RP ID / origin policy (folds into ``frappe/passkey.py``).
The UV / sign-count / BE-BS matrices arrive with the ceremony
engine. Resolution happens at enable time from pinned configuration — never on
a guest-request path, never from ``Host``/``X-Forwarded-*`` headers."""

import importlib.util
import re
from urllib.parse import urlsplit

import frappe
from frappe import _
from frappe.utils import cint

LOCALHOST_HOSTS = ("localhost", "127.0.0.1")


def webauthn_available() -> bool:
	return importlib.util.find_spec("webauthn") is not None


def resolve_rp_id(settings) -> str | None:
	"""Explicit `passkey_rp_id`, else the EXACT host of the site's configured
	``host_name`` — never a derived registrable/parent domain;
	widening is an explicit admin action via the knob."""
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


def resolve_origins(settings, rp_id: str) -> list[str]:
	"""Resolve exact trusted web origins without widening from the RP ID.

	The configured site origin is included when its host is inside ``rp_id``;
	additional origins must be listed explicitly. An RP ID is a credential scope,
	not evidence that its apex is an application origin.
	"""
	origins = []
	configured = resolve_site_origin(rp_id)
	if configured:
		host = (urlsplit(configured).hostname or "").lower()
		if host == rp_id or host.endswith("." + rp_id):
			origins.append(configured)
	for line in (settings.get("passkey_origins") or "").splitlines():
		line = line.strip()
		canonical = canonical_web_origin(line) if line else None
		origin = canonical or line
		if origin and origin not in origins:
			origins.append(origin)
	return origins


def canonical_web_origin(raw: str) -> str | None:
	"""Return the browser-canonical ``scheme://host[:port]`` form, or ``None``.

	Host and scheme are case-insensitive; browsers omit default ports in
	``clientDataJSON.origin``. Canonicalizing configuration prevents a valid
	``https://host:443`` entry from becoming an impossible exact match.
	"""
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
	"""Return the exact origin portion of the trusted ``host_name`` setting."""
	raw = (frappe.conf.get("host_name") or "").strip()
	if not raw:
		return None
	if "//" not in raw:
		raw = "https://" + raw
	return canonical_web_origin(raw)


def resolve_site_origin(rp_id: str) -> str | None:
	"""Return ``host_name``'s origin only when it falls within the RP scope."""
	configured = configured_site_origin()
	if not configured:
		return None
	host = (urlsplit(configured).hostname or "").lower()
	return configured if host == rp_id or host.endswith("." + rp_id) else None


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
		if rp_id and host != rp_id and not host.endswith("." + rp_id):
			frappe.throw(
				_(
					"Origin {0} cannot use RP ID {1}: its host must equal the RP ID or be a subdomain of it. Serving multiple unrelated domains requires Related Origin Requests, which is deferred."
				).format(origin, rp_id)
			)


def _is_dev_localhost(host: str) -> bool:
	return bool(frappe.conf.get("developer_mode")) and host in LOCALHOST_HOSTS


def lock_core_2fa_floor() -> int:
	"""Lock and return core's 2FA flag.

	Both the Passkey Settings forward validator and the System Settings reverse
	validator take this same ``tabSingles`` row lock. Concurrent saves therefore
	cannot each validate the other's stale pre-change value and commit a desync.
	"""
	rows = frappe.db.sql(
		"""select `value` from `tabSingles`
		where `doctype` = %s and `field` = %s
		for update""",
		("System Settings", "enable_two_factor_auth"),
	)
	return cint(rows[0][0] if rows else 0)


# ---------------------------------------------------------------------------
# Trusted app origins (native mobile)
# ---------------------------------------------------------------------------
# A native Android app presents its WebAuthn origin as
# ``android:apk-key-hash:<base64url-SHA256-of-the-signing-cert>`` — NOT
# ``https://<rp_id>``. These lines are appended to the ``expected_origin`` list the
# ceremony engine matches ``clientDataJSON.origin`` against, but they are EXEMPT from
# the web-origin validator (:func:`validate_origins`): they are not URLs, and web
# origin validation must never weaken. iOS needs no Trusted App Origin entry; it
# presents ``https://<rp_id>``, which must itself be present in the exact web-origin
# allowlist when that is the native app's asserted origin.

_APK_KEY_HASH_PREFIX = "android:apk-key-hash:"
# SHA-256 is 32 bytes → 43 unpadded base64url characters.
_APK_KEY_HASH_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def app_origins(settings) -> list[str]:
	"""The configured Trusted App Origins (``passkey_app_origins``), one per line,
	trimmed and de-duplicated. Pure read — shape validation is
	:func:`validate_app_origins` (settings save), never here."""
	origins: list[str] = []
	for line in (settings.get("passkey_app_origins") or "").splitlines():
		line = line.strip()
		if line and line not in origins:
			origins.append(line)
	return origins


def resolve_expected_origins(settings, rp_id: str) -> list[str]:
	"""The full ``expected_origin`` allowlist fed to the ceremony engine: the web
	origins (:func:`resolve_origins`) plus the Trusted App Origins
	(:func:`app_origins`). ``resolve_origins`` stays web-only, so the enable-time
	web-origin validator, the request-host pre-check and the settings display mirror
	never see an app origin — the native carve-out is strictly additive."""
	origins = resolve_origins(settings, rp_id)
	for origin in app_origins(settings):
		if origin not in origins:
			origins.append(origin)
	return origins


def validate_app_origins(settings) -> None:
	"""Save-time, fail-closed shape check for the Trusted App Origins. Each line
	must be ``android:apk-key-hash:<hash>`` where ``<hash>`` is the unpadded
	base64url SHA-256 (43 chars) of the app's signing certificate. iOS needs no
	Trusted App Origin entry, but its asserted ``https://<rp_id>`` must be configured
	as a web origin.

	Play App Signing note: the hash MUST come from Google's app-signing certificate
	(Play Console → App integrity → App signing), NOT the local upload key — the single
	most common native-passkey misconfiguration."""
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


# ---------------------------------------------------------------------------
# UV policy (per-ceremony matrix; wire vs enforcement)
# ---------------------------------------------------------------------------

# Wire `userVerification` requested per ceremony. The wire value is
# advisory; server enforcement is the functions below, never the wire string.
UV_WIRE = {
	"first_factor": "preferred",
	"second_factor": "discouraged",
	"registration_explicit": "preferred",
	"registration_conditional_create": "preferred",
	"confirmation": "required",
}

# First-factor UV enforcement outcomes.
UV_SESSION = "session"  # UV=1 ∧ uv_initialized=1 → passwordless session
UV_SETUP = "uv_setup"  # UV=1 ∧ uv_initialized=0 → inline step-up
UV_REJECT = "reject"  # UV=0 → a UV-less assertion never yields a passwordless session


def passwordless_uv_outcome(uv_bit: bool, uv_initialized: bool) -> str:
	"""First-factor gate. Passwordless requires **UV=1 AND uv_initialized**
	(the L3 §4 ``uvInitialized`` MUST-NOT: a false→true flip needs a second
	factor, so a bare UV=1 assertion never completes passwordless login by
	itself). Returns :data:`UV_SESSION` / :data:`UV_SETUP` / :data:`UV_REJECT`."""
	if not uv_bit:
		return UV_REJECT
	return UV_SESSION if uv_initialized else UV_SETUP


def resident_key_for_flow(flow: str) -> str:
	"""Fixed policy: ``required`` for an explicit add (discoverable
	first-factor credential), ``preferred`` for a conditional-create upgrade."""
	return "required" if flow == "explicit" else "preferred"


# ---------------------------------------------------------------------------
# Sign-count policy (app-side — the library check is disabled by passing
# credential_current_sign_count=0, else its internal hard-reject would silently
# turn the log+flag default into permanent hard-fail).
# ---------------------------------------------------------------------------

SIGN_COUNT_UNCHANGED = "unchanged"  # 0→0 (counter-less / synced authenticator) — pass, store 0
SIGN_COUNT_INCREMENT = "increment"  # new > stored — pass, store new
SIGN_COUNT_REPLAY = "replay"  # new == stored ≠ 0 — ALWAYS reject (not knob-controlled)
SIGN_COUNT_REGRESSION = "regression"  # new < stored — log+flag; reject iff hard-fail knob on


def classify_sign_count(stored: int, asserted: int) -> str:
	"""Matrix. Never writes the stored counter downward (the caller stores
	:func:`sign_count_to_store`)."""
	stored, asserted = int(stored), int(asserted)
	if asserted == 0 and stored == 0:
		return SIGN_COUNT_UNCHANGED
	if asserted > stored:
		return SIGN_COUNT_INCREMENT
	if asserted == stored:  # nonzero equal
		return SIGN_COUNT_REPLAY
	return SIGN_COUNT_REGRESSION  # asserted < stored (incl. asserted 0 while stored > 0)


def sign_count_to_store(stored: int, asserted: int) -> int:
	"""Upward-only: the increment case stores the new value; every other case
	keeps the stored value (never regress the counter)."""
	return int(asserted) if classify_sign_count(stored, asserted) == SIGN_COUNT_INCREMENT else int(stored)


# ---------------------------------------------------------------------------
# Backup eligibility / state
# ---------------------------------------------------------------------------


def backup_eligibility_mutated(stored_be: bool, asserted_be: bool) -> bool:
	"""BE is write-once at registration. An assertion whose BE flag
	differs from the stored value is a clone/forgery signal and fails the
	ceremony (stricter-than-spec). BS-without-BE illegality is
	caught inside py_webauthn (``InvalidBackupFlags``); this is the app-side
	mutation check the library does not perform."""
	return bool(stored_be) != bool(asserted_be)
