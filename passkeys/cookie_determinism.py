# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Deterministic ``sid`` cookies for UI-test sites.

Frappe re-issues ``Set-Cookie: sid`` on **every** response
(``frappe.auth.CookieManager.init_cookies``, called from
``HTTPRequest.__init__``) to slide the cookie expiry forward. On a UI-test
site that behaviour is a race generator: the browser's cookie jar is rewritten
by whichever response happens to arrive last, not by what the test last did.
A slow response to a request sent under a *previous* auth state lands late and

- re-installs a still-valid ``sid`` after the test logged out and cleared
  cookies, so ``/login`` 301s back to the desk (observed as the CI-only
  ``passkey_a11y`` failures — the screenshot shows the desk, with straggler
  ``getpage`` XHRs landing 200 in the failed test's own command log), or
- re-installs ``sid=Guest`` right after a login minted a fresh session, so the
  next request runs as Guest (observed as the CI-only ``passkey_second_factor``
  failure — ``cy.request`` sent ``cookie: sid=Guest`` straight after a 200
  ``verify_second_factor``).

Both reproduce deterministically in ``cypress/integration/sid_reseed_race.cy.js``
via a deliberately slow guest endpoint — no loaded CI runner required.

When the ``passkeys_deterministic_test_cookies`` site flag is set, the
``after_request`` hook below drops the *pending* sid re-seed while it is still
in ``frappe.local.cookie_manager.cookies`` — ``after_request`` hooks run before
``process_response`` flushes that dict onto the wire (``frappe.app.application``:
``run_after_request_hooks`` in the ``finally`` block, ``process_response`` →
``flush_cookies`` after it) — so the sid cookie changes ONLY on a genuine auth
transition:

- idempotent re-seed (pending equals the sid the request arrived with): dropped;
- stale downgrade (pending ``Guest`` for a request that arrived with a
  non-Guest sid, i.e. the session died between send and receive): dropped;
- genuine login (pending is a new sid the request did not arrive with): kept;
- logout: untouched — ``LoginManager.logout`` clears the cookie through
  ``CookieManager.to_delete`` (the expires-yesterday channel), which this hook
  never edits.

Production sites (flag absent) are byte-for-byte unaffected — sliding cookie
expiry depends on the re-seed, so this must never run outside a test site.
On the every-request hook path: imports only the stdlib and ``frappe``.
"""

from urllib.parse import unquote

import frappe
from frappe.utils import cint


def strip_stale_sid_reseed(response=None, request=None) -> None:
	"""``after_request`` hook: drop pending stale sid re-seeds on test sites."""
	conf = getattr(frappe.local, "conf", None)
	# cint, not bare truthiness: `set-config <flag> 0` without --parse stores the
	# STRING "0", and a truthy read would leave the hook (and the test helpers
	# gated on the same flag) enabled while the operator believes it is off.
	if not conf or not cint(conf.get("passkeys_deterministic_test_cookies")):
		return
	cookies = getattr(getattr(frappe.local, "cookie_manager", None), "cookies", None)
	if not cookies or "sid" not in cookies:
		return
	pending = cookies["sid"].get("value") or ""
	# Mirror CookieManager.set_cookie's deduplicate comparison: incoming
	# cookie values are quoted on the wire.
	arrived = unquote(request.cookies.get("sid", "")) if request is not None else ""
	if pending == arrived or (pending == "Guest" and arrived and arrived != "Guest"):
		cookies.pop("sid", None)
