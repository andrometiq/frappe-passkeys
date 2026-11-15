# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Well-known documents generated from Passkey Settings:

* Android — Digital Asset Links (``assetlinks.json``): the app package name plus its
  SHA-256 signing-certificate fingerprints, with the ``get_login_creds`` relation
  that enables credential sharing between the site and the app.
* iOS — App Site Association (``apple-app-site-association``): the ``webcredentials``
  service listing ``<Team ID>.<Bundle ID>``.
* W3C passkey endpoints (``passkey-endpoints``, a Working Draft): the ``enroll`` and
  ``manage`` URLs a password manager sends a user to.

Each is exposed as a guest-readable whitelisted endpoint that returns a **bare** JSON
document with an explicit ``application/json`` content type, a 200 and no redirect —
what the mobile OS, password managers and the association checkers require (they
reject a redirect, a wrong content type, or an envelope). A whitelisted method that
returns a ``werkzeug`` ``Response`` is emitted verbatim (no ``{"message": …}`` wrapper —
see ``frappe/handler.py`` / ``frappe/api/__init__.py``). Unconfigured ⇒ 404, which the
client reads as "nothing here". ``refuse_if_core_native`` is the canonical first guard,
per the app endpoint contract.

**Serving them at the real ``/.well-known/`` path.** Frappe reserves ``/.well-known/*``:
``frappe/app.py`` routes those GETs to ``handle_wellknown`` (OAuth/OpenID metadata
only, else 404) *before* the website router runs — so an app cannot claim those paths
via ``www/`` pages, ``website_route_rules`` or a ``page_renderer``. Map them at the
reverse proxy onto these endpoints with a one-time rule (see ``docs/mobile-apps.md`` and
``docs/install.md``); the served content then stays in lockstep with Passkey Settings
instead of a hand-maintained static file. ``webauthn`` is never imported here."""

import json
import re

import frappe
from frappe import _
from frappe.utils import cint
from werkzeug.wrappers import Response

from passkeys import policy
from passkeys.errors import refuse_if_core_native
from passkeys.request_security import rate_limit

# assetlinks.json relations: get_login_creds is the one that shares credentials
# between the site and the app; handle_all_urls is App Links / deep-linking —
# harmless to include and not the passkey trigger.
_ASSETLINKS_RELATIONS = (
	"delegate_permission/common.handle_all_urls",
	"delegate_permission/common.get_login_creds",
)


@frappe.whitelist(allow_guest=True, methods=["GET"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=120, seconds=60)
def assetlinks():
	"""Android Digital Asset Links (``/.well-known/assetlinks.json``). Emits the
	statement list built from settings; 404 when the package name / fingerprints are
	not both configured. Front it with reverse-proxy caching in production — it is a
	public, static-equivalent file (the per-IP rate limit here is only a DoS backstop)."""
	refuse_if_core_native()
	payload = build_assetlinks(frappe.get_cached_doc("Passkey Settings"))
	if payload is None:
		raise frappe.DoesNotExistError(_("assetlinks.json is not configured."))
	return _json_response(payload)


@frappe.whitelist(allow_guest=True, methods=["GET"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=120, seconds=60)
def apple_app_site_association():
	"""iOS App Site Association (``/.well-known/apple-app-site-association``). Emits the
	``webcredentials`` document built from settings; 404 when the Team ID / Bundle ID
	are not both configured."""
	refuse_if_core_native()
	payload = build_apple_app_site_association(frappe.get_cached_doc("Passkey Settings"))
	if payload is None:
		raise frappe.DoesNotExistError(_("apple-app-site-association is not configured."))
	return _json_response(payload)


@frappe.whitelist(allow_guest=True, methods=["GET"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=120, seconds=60)
def passkey_endpoints():
	"""W3C passkey endpoints (``/.well-known/passkey-endpoints``, Working Draft of
	2026-01-14). 404 unless a passkey login mode is on and the site has an https origin."""
	refuse_if_core_native()
	payload = build_passkey_endpoints(frappe.get_cached_doc("Passkey Settings"))
	if payload is None:
		raise frappe.DoesNotExistError(_("passkey-endpoints is not configured."))
	return _json_response(payload)


def build_assetlinks(settings) -> list | None:
	"""The ``assetlinks.json`` document (a list of statements) from settings, or
	``None`` when the Android package name and fingerprints are not both configured."""
	package = (settings.get("passkey_android_package_name") or "").strip()
	fingerprints = _fingerprints(settings.get("passkey_android_cert_fingerprints"))
	if not package or not fingerprints:
		return None
	return [
		{
			"relation": list(_ASSETLINKS_RELATIONS),
			"target": {
				"namespace": "android_app",
				"package_name": package,
				"sha256_cert_fingerprints": fingerprints,
			},
		}
	]


def build_apple_app_site_association(settings) -> dict | None:
	"""The ``apple-app-site-association`` document from settings, or ``None`` when the
	iOS Team ID and Bundle ID are not both configured."""
	team = (settings.get("passkey_ios_team_id") or "").strip()
	bundle = (settings.get("passkey_ios_bundle_id") or "").strip()
	if not team or not bundle:
		return None
	return {"webcredentials": {"apps": [f"{team}.{bundle}"]}}


def build_passkey_endpoints(settings) -> dict | None:
	"""``enroll`` and ``manage`` both name the ``/passkeys`` management page on the site's
	pinned https origin, or ``None`` when no passkey login mode is on or none resolves."""
	if not (cint(settings.get("login_with_passkey")) or cint(settings.get("passkey_as_second_factor"))):
		return None
	origin = policy.get_site_https_origin(settings)
	if not origin:
		return None
	url = f"{origin}/passkeys"
	return {"enroll": url, "manage": url}


def validate_association_settings(settings) -> None:
	"""Refuse association values the builders would drop or serve malformed."""
	lines = (settings.get("passkey_android_cert_fingerprints") or "").splitlines()
	for number, line in enumerate(lines, start=1):
		if line.strip() and not _fingerprints(line):
			frappe.throw(
				_(
					"Android fingerprint on line {0} is not a SHA-256 certificate fingerprint (64 hex characters, colons optional)."
				).format(number)
			)
	team = (settings.get("passkey_ios_team_id") or "").strip()
	if team and not re.fullmatch(r"[A-Z0-9]{10}", team):
		frappe.throw(_("iOS Team ID must be 10 uppercase letters or digits, for example ABCDE12345."))
	bundle = (settings.get("passkey_ios_bundle_id") or "").strip()
	if bundle and not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", bundle):
		frappe.throw(_("iOS Bundle ID must be in reverse-DNS form, for example com.example.app."))


def _fingerprints(raw) -> list[str]:
	"""Normalize the configured SHA-256 fingerprints to uppercase colon-grouped hex
	(``AB:CD:…``), one per non-empty line, de-duplicated. A valid fingerprint is
	exactly 32 bytes (64 hex characters); malformed or truncated lines are dropped.
	A leading keytool-style ``SHA256:`` / ``SHA-256 =`` label is tolerated."""
	out: list[str] = []
	for line in (raw or "").splitlines():
		line = re.sub(r"(?i)^\s*sha-?256\s*[:=]?", "", line).strip()
		hexits = re.sub(r"\s+", "", line.replace(":", ""))
		if not re.fullmatch(r"[0-9A-Fa-f]{64}", hexits):
			continue
		hexits = hexits.upper()
		grouped = ":".join(hexits[i : i + 2] for i in range(0, len(hexits), 2))
		if grouped not in out:
			out.append(grouped)
	return out


def _json_response(payload) -> Response:
	"""A bare JSON document with an explicit ``application/json`` content type and no
	redirect — exactly what the Android / iOS association checkers require."""
	response = Response(json.dumps(payload, indent=2), content_type="application/json", status=200)
	response.headers["Cache-Control"] = "public, max-age=3600"
	response.headers["X-Content-Type-Options"] = "nosniff"
	return response
