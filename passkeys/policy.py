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
