# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Mobile-app association files, generated from Passkey Settings so a native
iOS/Android app can share the site's passkeys (same RP ID):

* Android — Digital Asset Links (``assetlinks.json``): the app package name plus its
  SHA-256 signing-certificate fingerprints, with the ``get_login_creds`` relation
  that enables credential sharing between the site and the app.
* iOS — App Site Association (``apple-app-site-association``): the ``webcredentials``
  service listing ``<Team ID>.<Bundle ID>``.

Both are exposed as guest-readable whitelisted endpoints that return a **bare** JSON
document with an explicit ``application/json`` content type, a 200 and no redirect —
what the mobile OS and the association checkers require (they reject a redirect, a
wrong content type, or an envelope). A whitelisted method that returns a ``werkzeug``
``Response`` is emitted verbatim (no ``{"message": …}`` wrapper — see
``frappe/handler.py`` / ``frappe/api/__init__.py``). Unconfigured ⇒ 404, which the OS
reads as "no association". ``refuse_if_core_native`` is the canonical first guard, per
the app endpoint contract.

**Serving them at the real ``/.well-known/`` path.** Frappe reserves ``/.well-known/*``:
``frappe/app.py`` routes those GETs to ``handle_wellknown`` (OAuth/OpenID metadata
only, else 404) *before* the website router runs — so an app cannot claim those paths
via ``www/`` pages, ``website_route_rules`` or a ``page_renderer``. Map them at the
reverse proxy onto these endpoints with a one-time rule (see ``docs/mobile-apps.md``);
the served content then stays in lockstep with the Trusted App Origins setting instead
of a hand-maintained static file. ``webauthn`` is never imported here."""

import json
import re

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from werkzeug.wrappers import Response

from passkeys.passkey import refuse_if_core_native

# assetlinks.json relations: get_login_creds is the one that shares credentials
# between the site and the app; handle_all_urls is App Links / deep-linking —
# harmless to include and not the passkey trigger.
_ASSETLINKS_RELATIONS = (
	"delegate_permission/common.handle_all_urls",
	"delegate_permission/common.get_login_creds",
)


@frappe.whitelist(allow_guest=True, methods=["GET"])
@rate_limit(limit=120, seconds=60)
def assetlinks():
	"""Android Digital Asset Links (``/.well-known/assetlinks.json``). Emits the
	statement list built from settings; 404 when the package name / fingerprints are
	not both configured. Front it with reverse-proxy caching in production — it is a
	public, static-equivalent file (the per-IP rate limit here is only a DoS backstop)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	payload = build_assetlinks(frappe.get_cached_doc("Passkey Settings"))
	if payload is None:
		raise frappe.DoesNotExistError(_("assetlinks.json is not configured."))
	return _json_response(payload)


@frappe.whitelist(allow_guest=True, methods=["GET"])
@rate_limit(limit=120, seconds=60)
def apple_app_site_association():
	"""iOS App Site Association (``/.well-known/apple-app-site-association``). Emits the
	``webcredentials`` document built from settings; 404 when the Team ID / Bundle ID
	are not both configured."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	payload = build_apple_app_site_association(frappe.get_cached_doc("Passkey Settings"))
	if payload is None:
		raise frappe.DoesNotExistError(_("apple-app-site-association is not configured."))
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


def _fingerprints(raw) -> list[str]:
	"""Normalize the configured SHA-256 fingerprints to uppercase colon-grouped hex
	(``AB:CD:…``), one per non-empty line, de-duplicated; lines carrying no hex are
	dropped. A leading keytool-style ``SHA256:`` / ``SHA-256 =`` label is tolerated
	so a copied ``keytool -list`` line normalizes cleanly (without it the ``A`` in
	``SHA256`` would be salvaged as hex); paste one fingerprint per line — colons
	optional."""
	out: list[str] = []
	for line in (raw or "").splitlines():
		line = re.sub(r"(?i)^\s*sha-?256\s*[:=]?", " ", line)
		hexits = re.sub(r"[^0-9A-Fa-f]", "", line).upper()
		if not hexits:
			continue
		grouped = ":".join(hexits[i : i + 2] for i in range(0, len(hexits), 2))
		if grouped not in out:
			out.append(grouped)
	return out


def _json_response(payload) -> Response:
	"""A bare JSON document with an explicit ``application/json`` content type and no
	redirect — exactly what the Android / iOS association checkers require."""
	return Response(json.dumps(payload, indent=2), content_type="application/json", status=200)
