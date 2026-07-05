# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""RP ID / origin policy (DESIGN-v1 §9.2; folds into ``frappe/passkey.py``).
The UV / sign-count / BE-BS matrices (§3.6/§3.7) arrive with the ceremony
engine. Resolution happens at enable time from pinned configuration — never on
a guest-request path, never from ``Host``/``X-Forwarded-*`` headers."""

import importlib.util
from urllib.parse import urlsplit

import frappe
from frappe import _

LOCALHOST_HOSTS = ("localhost", "127.0.0.1")


def webauthn_available() -> bool:
	return importlib.util.find_spec("webauthn") is not None


def resolve_rp_id(settings) -> str | None:
	"""Explicit `passkey_rp_id`, else the EXACT host of the site's configured
	``host_name`` — never a derived registrable/parent domain (pass-3 F3-1);
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
	"""Expected origins: ``https://{rp_id}`` + the `passkey_origins` lines
	(exact-match allowlist, explicit ports allowed)."""
	origins = [f"https://{rp_id}"]
	for line in (settings.get("passkey_origins") or "").splitlines():
		line = line.strip()
		if line and line not in origins:
			origins.append(line)
	return origins


def validate_origins(settings, rp_id: str) -> None:
	"""Enable-time, fail-closed (§9.2): HTTPS only (``http://localhost`` under
	developer mode), and every origin host within the RP ID's registrable
	scope — an out-of-scope origin passes every server check and then dies
	client-side with a browser SecurityError, forever (B-F11)."""
	for origin in resolve_origins(settings, rp_id):
		parts = urlsplit(origin)
		host = (parts.hostname or "").lower()
		if not host or parts.path not in ("", "/") or parts.query or parts.fragment:
			frappe.throw(
				_("Invalid passkey origin {0}: expected scheme://host[:port], one per line").format(origin)
			)
		if parts.scheme != "https":
			if parts.scheme == "http" and _is_dev_localhost(host):
				continue
			frappe.throw(
				_(
					"Passkey origin {0} must use HTTPS (http is allowed only for localhost while developer mode is on)"
				).format(origin)
			)
		if host != rp_id and not host.endswith("." + rp_id):
			frappe.throw(
				_(
					"Origin {0} cannot use RP ID {1}: its host must equal the RP ID or be a subdomain of it. Serving multiple unrelated domains requires Related Origin Requests, which is deferred."
				).format(origin, rp_id)
			)


def _is_dev_localhost(host: str) -> bool:
	return bool(frappe.conf.get("developer_mode")) and host in LOCALHOST_HOSTS


# ---------------------------------------------------------------------------
# UV policy (§3.7 per-ceremony matrix; wire vs enforcement)
# ---------------------------------------------------------------------------

# Wire `userVerification` requested per ceremony (§3.7 table). The wire value is
# advisory; server enforcement is the functions below, never the wire string.
UV_WIRE = {
	"first_factor": "preferred",
	"second_factor": "discouraged",
	"registration_explicit": "preferred",
	"registration_conditional_create": "preferred",
	"confirmation": "required",
}

# First-factor UV enforcement outcomes (§3.1 step 11 / §3.7).
UV_SESSION = "session"  # UV=1 ∧ uv_initialized=1 → passwordless session
UV_SETUP = "uv_setup"  # UV=1 ∧ uv_initialized=0 → §3.4 inline step-up
UV_REJECT = "reject"  # UV=0 → a UV-less assertion never yields a passwordless session


def passwordless_uv_outcome(uv_bit: bool, uv_initialized: bool) -> str:
	"""§3.7 first-factor gate. Passwordless requires **UV=1 AND uv_initialized**
	(the L3 §4 ``uvInitialized`` MUST-NOT: a false→true flip needs a second
	factor, so a bare UV=1 assertion never completes passwordless login by
	itself). Returns :data:`UV_SESSION` / :data:`UV_SETUP` / :data:`UV_REJECT`."""
	if not uv_bit:
		return UV_REJECT
	return UV_SESSION if uv_initialized else UV_SETUP


def resident_key_for_flow(flow: str) -> str:
	"""§3.2 / §9.1 fixed policy: ``required`` for an explicit add (discoverable
	first-factor credential), ``preferred`` for a conditional-create upgrade."""
	return "required" if flow == "explicit" else "preferred"


# ---------------------------------------------------------------------------
# Sign-count policy (§3.6; app-side — the library check is disabled by passing
# credential_current_sign_count=0, else its internal hard-reject would silently
# turn the log+flag default into permanent hard-fail).
# ---------------------------------------------------------------------------

SIGN_COUNT_UNCHANGED = "unchanged"  # 0→0 (counter-less / synced authenticator) — pass, store 0
SIGN_COUNT_INCREMENT = "increment"  # new > stored — pass, store new
SIGN_COUNT_REPLAY = "replay"  # new == stored ≠ 0 — ALWAYS reject (not knob-controlled)
SIGN_COUNT_REGRESSION = "regression"  # new < stored — log+flag; reject iff hard-fail knob on


def classify_sign_count(stored: int, asserted: int) -> str:
	"""§3.6 matrix. Never writes the stored counter downward (the caller stores
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
# Backup eligibility / state (§3.6)
# ---------------------------------------------------------------------------


def backup_eligibility_mutated(stored_be: bool, asserted_be: bool) -> bool:
	"""BE is write-once at registration (§2.1). An assertion whose BE flag
	differs from the stored value is a clone/forgery signal and fails the
	ceremony (stricter-than-spec, stated §3.6). BS-without-BE illegality is
	caught inside py_webauthn (``InvalidBackupFlags``); this is the app-side
	mutation check the library does not perform."""
	return bool(stored_be) != bool(asserted_be)
