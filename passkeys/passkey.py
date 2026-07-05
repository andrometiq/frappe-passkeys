# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted passkey endpoints (folds into ``frappe/passkey.py`` on the core
merge). This module holds the typed-error wire contract (DESIGN-v1 §3), the
first-factor passwordless login ceremony (`begin_login`/`verify_login`), the
uv-setup step-up (`complete_uv_setup`), the guest translations endpoint, and
the User cascade.

``webauthn`` (via ``passkeys.engine``) is imported **lazily inside the ceremony
endpoint bodies** (§1.3 hook-path import discipline): this module is imported by
``session.py`` and ``api/registration.py`` at their top level, so a broken
crypto wheel must never reach import time. ``policy``/``state`` are webauthn-free
and safe to import at module scope."""

import base64
import hashlib

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import cint, now_datetime

from passkeys import policy, state

# Typed-error wire contract (§3): every typed error is an exception class —
# frappe's `report_error` emits the class name as `exc_type`, which is the wire
# value clients match on. Structured payloads ride `frappe.local.response`
# keys set before raising, never the translated message text.


class CeremonyExpired(frappe.AuthenticationError):
	"""Single-use state consumed, expired, evicted, or never existed (§4.2)."""


class UnknownCredential(frappe.AuthenticationError):
	"""Assertion references no known credential; feeds the Signal API (§3.1)."""


class UVSetupRequired(frappe.AuthenticationError):
	"""UV=1 assertion against a credential with uv_initialized=0 (§3.4/§3.7)."""


class PasskeyConfirmationRequired(frappe.AuthenticationError):
	"""A `@passkey_protected` action needs a fresh confirmation grant (§7.2)."""


class PasskeyServedByCore(frappe.ValidationError):
	"""Every app endpoint refuses when core serves passkeys natively (§11)."""

	http_status_code = 417


def cascade_delete_user_artifacts(doc, method=None):
	"""User on_trash: drop the user's credential and handle rows (§2.2)."""
	for doctype in ("WebAuthn Credential", "WebAuthn User Handle"):
		frappe.db.delete(doctype, {"user": doc.name})


# ===========================================================================
# First-factor passwordless login (J1/J2/J3) — §3.1
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=30, seconds=60)
def begin_login():
	"""Mint discoverable-credential assertion options + a single-use ceremony
	state, and set/refresh the guest binder cookie (§3.1 / §4.3).

	No identifier is ever taken — discoverable-only, which structurally removes
	the credential-broadcast flaw and the begin-response enumeration oracle.
	Always answers 200 with the mode flags (the bundle's only config channel);
	``state_id`` + ``options`` + binder cookie are minted **only** when
	``login_with_passkey`` is on (§3.0 enablement matrix)."""
	settings = frappe.get_cached_doc("Passkey Settings")
	first_factor = bool(cint(settings.login_with_passkey))
	second_factor = bool(cint(settings.passkey_as_second_factor))
	response = {
		"enabled": first_factor or second_factor,
		"modes": {"first_factor": first_factor, "second_factor": second_factor},
	}
	if not first_factor:
		# Pure config for the bundle: no state, no cookie (mode-off).
		return response

	from passkeys import engine

	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		# Mode on but unconfigured — fail closed uniformly (§3.1 fail-closed arm).
		raise frappe.AuthenticationError(_("Passkeys are not available on this host."))
	origins = policy.resolve_origins(settings, rp_id)
	_enforce_request_host(origins)

	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id,
		allow_credentials=None,  # discoverable-only — empty allowCredentials
		user_verification=policy.UV_WIRE["first_factor"],
	)
	binder_value = state.set_binder_cookie()
	state_id = state.store_ceremony(
		{
			"v": 1,
			"type": "login",
			"challenge_b64": challenge_b64,
			"rp_id": rp_id,
			"origins": origins,
			"binder_sha256": state.binder_hash(binder_value),
			"created_at": now_datetime().isoformat(),
		}
	)
	response["state_id"] = state_id
	response["options"] = options
	return response


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=60)
def verify_login(state_id: str, credential):
	"""Verify a discoverable assertion, resolve the account from its
	``userHandle`` + credential id, enforce the UV outcome policy, and mint a
	session via the one sanctioned seam (§3.1 PENDING ladder).

	Success returns ``None`` so the core login envelope set by ``login_as`` /
	``post_login`` (``message: "Logged In"``, ``home_page``) stays at the top
	level — the client redirects via the returned ``home_page`` only, never a
	hardcoded ``/app`` or ``/desk``."""
	from passkeys import engine

	credential = _as_dict(credential)

	# 1. atomic single-use consume; a login state can never be a register state
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "login":
		raise CeremonyExpired(_("That took too long — please try again."))

	# 2. binder cookie must match the value bound at begin (login-CSRF defence)
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# 3b. mode still enabled (mid-ceremony admin disable fails closed)
	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.login_with_passkey):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# 4. request host ∈ the origins bound at begin
	_enforce_request_host(record.get("origins") or [])

	# 6. resolve the account: userHandle is REQUIRED for discoverable login
	response_block = credential.get("response") or {}
	user_handle = response_block.get("userHandle")
	cred_id = credential.get("id") or credential.get("rawId")
	if not user_handle or not cred_id:
		raise UnknownCredential(_("Passkey could not be verified."))

	handle_user = frappe.db.get_value("WebAuthn User Handle", {"handle": user_handle}, "user")
	sha = hashlib.sha256(_b64url_decode(cred_id)).hexdigest()
	cred = frappe.db.get_value(
		"WebAuthn Credential",
		{"credential_id_sha256": sha},
		["name", "user", "enabled", "public_key", "sign_count", "backup_eligible", "uv_initialized"],
		as_dict=True,
	)
	if not cred:
		# truly-unknown id — safe pre-auth Signal feed (§3.1 step 6)
		raise UnknownCredential(_("Passkey could not be verified."))
	# ownership + enabled: uniform failure (no cross-user existence oracle)
	if not handle_user or cred.user != handle_user or not cint(cred.enabled):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# 7-9. verify the assertion (crossOrigin/BE-BS/sign-count enforced app-side)
	result = engine.verify_authentication(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		credential_public_key=cred.public_key,
		stored_sign_count=cint(cred.sign_count),
		stored_backup_eligible=bool(cint(cred.backup_eligible)),
		require_user_verification=False,  # §3.7 layered below, never at the library
		sign_count_hard_fail=bool(cint(settings.passkey_sign_count_hard_fail)),
	)

	# 10. account still enabled?
	if not cint(frappe.db.get_value("User", cred.user, "enabled")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# 11. UV gate (§3.7): passwordless ONLY on UV=1 ∧ uv_initialized=1
	outcome = policy.passwordless_uv_outcome(result.user_verified, bool(cint(cred.uv_initialized)))
	if outcome == policy.UV_REJECT:
		raise frappe.AuthenticationError(
			_("This passkey can't complete a passwordless sign-in. Please verify another way.")
		)
	if outcome == policy.UV_SETUP:
		setup_id = state.store_uv_setup(
			{
				"v": 1,
				"user": cred.user,
				"credential": cred.name,
				"binder_sha256": record.get("binder_sha256"),
				"sign_count_to_store": result.sign_count_to_store,
				"backup_state": int(result.backup_state),
			}
		)
		frappe.local.response["setup_id"] = setup_id
		raise UVSetupRequired(_("One more step to finish setting up this passkey."))

	# 12. SESSION
	_advance_credential(cred.name, result)
	frappe.local.response["authenticator_attachment"] = credential.get("authenticatorAttachment")
	_mint_session(cred.user)
	return None


# ===========================================================================
# uv-setup step-up — the uv_initialized repair (guest) — §3.4
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=5, seconds=300)
def complete_uv_setup(setup_id: str, pwd: str):
	"""Authorize the ``uv_initialized`` false→true flip with a one-time password
	check (§3.4). The setup record was minted **only** by a fully verified UV=1
	assertion (`verify_login` step 11) — possession + UV already proven; this
	adds the knowledge factor L3 §7.2 requires for the flip.

	Stays available under core ``disable_user_pass_login`` (B-F4): the password
	here is a factor for the flip, not a password *login*. Sets
	``frappe.local.flags.passkey_login`` before ``login_as`` (F3-2) so a
	``passkey_only_login=1`` user repairing a conditional-create credential does
	not trip their own §9.3 veto mid-repair."""
	from frappe.utils.password import check_password

	record = state.consume_uv_setup(setup_id)
	if not record:
		raise CeremonyExpired(_("That took too long — please try again."))
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	user = record["user"]
	# app-owned per-user password-oracle throttle (the core tracker is off by
	# default; this endpoint is a password oracle the app introduces — §3.0)
	if state.is_password_throttled(user):
		raise frappe.AuthenticationError(_("Too many attempts. Please try again later."))

	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.login_with_passkey):  # verify-side mode re-check
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	try:
		check_password(user, pwd)
	except frappe.AuthenticationError:
		state.record_password_failure(user)
		raise frappe.AuthenticationError(_("Incorrect password."))
	state.clear_password_failures(user)

	credential = record.get("credential")
	if credential and frappe.db.exists("WebAuthn Credential", credential):
		frappe.db.set_value(
			"WebAuthn Credential",
			credential,
			{
				"uv_initialized": 1,
				"sign_count": cint(record.get("sign_count_to_store")),
				"backup_state": cint(record.get("backup_state")),
				"last_used_at": now_datetime(),
				"last_used_ip": _request_ip(),
			},
			update_modified=False,
		)

	frappe.local.flags.passkey_login = True
	_mint_session(user)
	return None


# ===========================================================================
# Guest translations endpoint (§5.6) — REQUIRED on v15/v16 (native guest i18n
# delivery is develop-only); the login bundle merges the catalog client-side.
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_app_translations(version: str | None = None):
	"""Return the passkeys app's translation catalog for the request language
	(§5.6). Wraps ``get_translations_from_apps`` scoped to this app only; the
	bundle fetches once, memoizes on the app-controlled ``version`` param, and
	``Object.assign``-merges into ``frappe._messages`` (never clobbers the
	Web-Form / core catalog). Without it, non-English v15/v16 sites see English
	passkey UI — a release blocker."""
	from frappe.translate import get_translations_from_apps

	lang = getattr(frappe.local, "lang", None) or "en"
	return get_translations_from_apps(lang, apps=["passkeys"])


# ---------------------------------------------------------------------------
# session mint (the one auditable choke point — §1.2)
# ---------------------------------------------------------------------------


def _mint_session(user: str) -> None:
	"""Funnel every passkey session through ``login_as`` → ``post_login`` (§1.2)
	— full ``on_login``/``on_session_creation`` hooks, IP/hour checks, fresh
	session + cookies, Activity Log; never a fresh ``LoginManager()`` mid-flow
	(the PR #34181 mistake). ``frappe.local.flags.passkey_login`` must already be
	set by the caller so ``seed_sudo_window`` classifies the window as passkey."""
	login_manager = getattr(frappe.local, "login_manager", None)
	if login_manager is None:
		# No request-time LoginManager (direct-call / unit path): build one.
		from frappe.auth import LoginManager

		login_manager = LoginManager()
		frappe.local.login_manager = login_manager
	login_manager.login_as(user)


def _advance_credential(name: str, result) -> None:
	"""Persist the upward-only sign-count, refreshed backup state, and last-used
	bookkeeping after a successful assertion (§3.1 step 12 / §3.6). A flagged
	sign-count regression is recorded but never blocks (unless hard-fail already
	raised inside the engine)."""
	values = {
		"sign_count": result.sign_count_to_store,
		"backup_state": int(result.backup_state),
		"last_used_at": now_datetime(),
		"last_used_ip": _request_ip(),
	}
	if result.sign_count_regression:
		values["flagged"] = 1
		values["flagged_reason"] = "sign_count_regression"
	frappe.db.set_value("WebAuthn Credential", name, values, update_modified=False)


# ---------------------------------------------------------------------------
# guest-ceremony helpers
# ---------------------------------------------------------------------------


def _enforce_request_host(origins: list) -> None:
	"""Fail-closed host membership (§3.1 / §9.2). No-ops without an HTTP request
	(direct-call unit paths) — the library's ``expected_origin`` check against
	clientDataJSON is the binding enforcement; this is the ops-diagnosable
	pre-check that also powers the begin-side uniform 401."""
	origin = _request_origin()
	if origin is None:
		return
	if origin not in origins:
		raise frappe.AuthenticationError(_("Passkeys are not available on this host."))


def _request_origin() -> str | None:
	request = getattr(frappe.local, "request", None)
	headers = getattr(request, "headers", None) if request is not None else None
	return headers.get("Origin") if headers is not None else None


def _request_ip() -> str | None:
	return getattr(frappe.local, "request_ip", None)


def _b64url_decode(value: str) -> bytes:
	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _as_dict(value):
	import json

	return json.loads(value) if isinstance(value, str) else value
