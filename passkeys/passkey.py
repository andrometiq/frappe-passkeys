# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted passkey endpoints (folds into ``frappe/passkey.py`` on the core
merge). This module holds the typed-error wire contract, the
first-factor passwordless login ceremony (`begin_login`/`verify_login`), the
uv-setup step-up (`complete_uv_setup`), the guest translations endpoint, and
the User cascade.

``webauthn`` (via ``passkeys.engine``) is imported **lazily inside the ceremony
endpoint bodies** (hook-path import discipline): this module is imported by
``session.py`` and ``api/registration.py`` at their top level, so a broken
crypto wheel must never reach import time. ``policy``/``state`` are webauthn-free
and safe to import at module scope."""

import base64
import hashlib
import json

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import cint, now_datetime

from passkeys import install, policy, state

# Attempt cap for the failed-passkey second-factor retry: a leg-2
# verify failure re-arms a fresh state up to this many attempts, then falls back
# to the password form. Core-OTP parity (a wrong token doesn't destroy tmp_id).
SECOND_FACTOR_MAX_ATTEMPTS = 3

# Typed-error wire contract: every typed error is an exception class —
# frappe's `report_error` emits the class name as `exc_type`, which is the wire
# value clients match on. Structured payloads ride `frappe.local.response`
# keys set before raising, never the translated message text.


class CeremonyExpired(frappe.AuthenticationError):
	"""Single-use state consumed, expired, evicted, or never existed."""


class UnknownCredential(frappe.AuthenticationError):
	"""Assertion references no known credential; feeds the Signal API."""


class UVSetupRequired(frappe.AuthenticationError):
	"""UV=1 assertion against a credential with uv_initialized=0."""


class PasskeyConfirmationRequired(frappe.AuthenticationError):
	"""A `@passkey_protected` action needs a fresh confirmation grant."""


class PasskeyServedByCore(frappe.ValidationError):
	"""Every app endpoint refuses when core serves passkeys natively."""

	http_status_code = 417


def refuse_if_core_native() -> None:
	"""Dormant-shell contract: the canonical FIRST guard on every whitelisted
	app endpoint. The moment core serves passkeys natively the app raises the typed
	417 so the two implementations never mint sessions or mutate credentials in
	parallel ("every app endpoint raises typed PasskeyServedByCore"). Every
	endpoint module — confirm.py, passkey.py, api/registration.py, api/credentials.py
	— routes through THIS one helper (no duplicated switch logic), and it rides the
	shared ``install.dormant`` switch so the first guarded surface hit also emits the
	one-time uninstall advisory."""
	if install.dormant():
		raise PasskeyServedByCore(_("This site serves passkeys natively."))


def cascade_delete_user_artifacts(doc, method=None):
	"""User on_trash: drop the user's credential and handle rows.

	Dormant no-op when core serves passkeys natively: core owns the cascade
	then, so a parallel app cascade would be the "double on_trash" coupling.
	A silent return — never a raise: a doc-event throw would block User
	deletion site-wide."""
	if install.dormant():
		return
	for doctype in ("WebAuthn Credential", "WebAuthn User Handle"):
		frappe.db.delete(doctype, {"user": doc.name})


# ===========================================================================
# First-factor passwordless login
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=30, seconds=60)
def begin_login():
	"""Mint discoverable-credential assertion options + a single-use ceremony
	state, and set/refresh the guest binder cookie.

	No identifier is ever taken — discoverable-only, which structurally removes
	the credential-broadcast flaw and the begin-response enumeration oracle.
	Always answers 200 with the mode flags (the bundle's only config channel);
	``state_id`` + ``options`` + binder cookie are minted **only** when
	``login_with_passkey`` is on (enablement matrix)."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
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
		# Mode on but unconfigured — fail closed uniformly (fail-closed arm).
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
	session via the one sanctioned seam (PENDING ladder).

	Success returns ``None`` so the core login envelope set by ``login_as`` /
	``post_login`` (``message: "Logged In"``, ``home_page``) stays at the top
	level — the client redirects via the returned ``home_page`` only, never a
	hardcoded ``/app`` or ``/desk``."""
	refuse_if_core_native()  # dormant-shell (before the crypto engine import)
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
		# truly-unknown id — safe pre-auth Signal feed
		raise UnknownCredential(_("Passkey could not be verified."))
	# ownership + enabled: uniform failure (no cross-user existence oracle)
	if not handle_user or cred.user != handle_user or not cint(cred.enabled):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# 7-11. verify the assertion (crossOrigin/BE-BS/sign-count enforced app-side) +
	# the account-enabled recheck + the UV gate. Any genuine FAILURE past credential
	# resolution feeds core's LoginAttemptTracker for this user so a
	# passkey brute-force shares the same consecutive-failure lockout as a bad
	# password — without leaking user existence (the wire stays a uniform 401; no
	# lock exception is raised here). UV_SETUP is a legitimate step-up, NOT a failure,
	# so it is handled OUTSIDE this guard.
	try:
		result = engine.verify_authentication(
			credential=credential,
			expected_challenge=record["challenge_b64"],
			expected_rp_id=record["rp_id"],
			expected_origin=record["origins"],
			credential_public_key=cred.public_key,
			stored_sign_count=cint(cred.sign_count),
			stored_backup_eligible=bool(cint(cred.backup_eligible)),
			require_user_verification=False,  # layered below, never at the library
			sign_count_hard_fail=bool(cint(settings.passkey_sign_count_hard_fail)),
		)
		# 10. account still enabled?
		if not cint(frappe.db.get_value("User", cred.user, "enabled")):
			raise frappe.AuthenticationError(_("Passkey could not be verified."))
		# 11. UV gate: passwordless ONLY on UV=1 ∧ uv_initialized=1
		outcome = policy.passwordless_uv_outcome(result.user_verified, bool(cint(cred.uv_initialized)))
		if outcome == policy.UV_REJECT:
			raise frappe.AuthenticationError(
				_("This passkey can't complete a passwordless sign-in. Please verify another way.")
			)
	except frappe.AuthenticationError:
		_track_verify_failure(cred.user)
		raise

	if outcome == policy.UV_SETUP:
		setup_id = state.store_uv_setup(
			{
				"v": 1,
				"user": cred.user,
				"credential": cred.name,
				"binder_sha256": record.get("binder_sha256"),
				"sign_count_to_store": result.sign_count_to_store,
				# SEC-2: carry the regression signal — this leg does NOT call
				# _advance_credential (the sole flag+notify site), so complete_uv_setup
				# must re-apply the flag; without it a clone's first-UV=1 regression
				# is lost under the default soft policy.
				"sign_count_regression": bool(result.sign_count_regression),
				"backup_state": int(result.backup_state),
			}
		)
		frappe.local.response["setup_id"] = setup_id
		raise UVSetupRequired(_("One more step to finish setting up this passkey."))

	# 12. SESSION — flag before login_as: the veto exemption for a
	# passkey_only_login=1 user, and the "passkey" sudo-window classification.
	_advance_credential(cred.name, result)
	frappe.local.response["authenticator_attachment"] = credential.get("authenticatorAttachment")
	frappe.local.flags.passkey_login = True
	_mint_session(cred.user)
	return None


# ===========================================================================
# uv-setup step-up — the uv_initialized repair (guest)
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=5, seconds=300)
def complete_uv_setup(setup_id: str, pwd: str):
	"""Authorize the ``uv_initialized`` false→true flip with a one-time password
	check. The setup record was minted **only** by a fully verified UV=1
	assertion (`verify_login` step 11) — possession + UV already proven; this
	adds the knowledge factor L3 §7.2 requires for the flip.

	Stays available under core ``disable_user_pass_login``: the password
	here is a factor for the flip, not a password *login*. Sets
	``frappe.local.flags.passkey_login`` before ``login_as`` so a
	``passkey_only_login=1`` user repairing a conditional-create credential does
	not trip their own veto mid-repair."""
	refuse_if_core_native()  # dormant-shell (before the password-check import)
	from frappe.utils.password import check_password

	record = state.consume_uv_setup(setup_id)
	if not record:
		raise CeremonyExpired(_("That took too long — please try again."))
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	user = record["user"]
	# app-owned per-user password-oracle throttle (the core tracker is off by
	# default; this endpoint is a password oracle the app introduces)
	if state.is_password_throttled(user):
		raise frappe.AuthenticationError(_("Too many attempts. Please try again later."))

	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.login_with_passkey):  # verify-side mode re-check
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	try:
		check_password(user, pwd)
	except frappe.AuthenticationError:
		state.record_password_failure(user)
		_track_verify_failure(user)  # a wrong-password step-up feeds the tracker too
		raise frappe.AuthenticationError(_("Incorrect password."))
	state.clear_password_failures(user)

	# C4: the uv-setup record lives up to 180 s post-assertion — re-check
	# User.enabled just before minting, exactly as verify_login step 10 does, so a
	# mid-window admin disable fails closed (no session, no credential mutation).
	if not cint(frappe.db.get_value("User", user, "enabled")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	credential = record.get("credential")
	if credential and frappe.db.exists("WebAuthn Credential", credential):
		# SEC-3: the stashed sign_count is an ABSOLUTE captured at verify_login time;
		# a concurrent 2FA/confirm advance may have raised the stored counter past it.
		# Re-read the live value and store the upward-only policy max — never regress
		# a counter a concurrent advance already raised (weakening clone detection).
		fresh = cint(frappe.db.get_value("WebAuthn Credential", credential, "sign_count"))
		values = {
			"uv_initialized": 1,
			"sign_count": policy.sign_count_to_store(fresh, cint(record.get("sign_count_to_store"))),
			"backup_state": cint(record.get("backup_state")),
			"last_used_at": now_datetime(),
			"last_used_ip": _request_ip(),
		}
		# SEC-2: this uv-setup leg is the SOLE advance for its assertion — re-apply the
		# flagged sign-count regression + owner notification exactly as
		# _advance_credential would (soft policy: flag, never block).
		newly_flagged = _apply_sign_count_flag(credential, bool(record.get("sign_count_regression")), values)
		frappe.db.set_value("WebAuthn Credential", credential, values, update_modified=False)
		_notify_if_newly_flagged(credential, newly_flagged)

	frappe.local.flags.passkey_login = True
	_mint_session(user)
	return None


# ===========================================================================
# Second factor (password → passkey step-up)
#
# Modeled on core's LDAP alternate-flow precedent (authenticate by our own
# means → optionally run core's 2FA overlay → post_login), speaking core's own
# two-request `verification` + `tmp_id` envelope so the wire is byte-compatible
# with a future native core implementation. ZERO monkeypatch: the endpoints are
# whitelisted, the floor is structural (core 2FA kept ON), and the session
# is minted only through the one `_mint_session` (login_as → post_login) choke
# point. Method paths are pinned by the committed login bundle
# (`passkeys.passkey.login_with_password` / `.verify_second_factor` /
# `.fallback_to_otp`).
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=60)
def login_with_password(usr: str, pwd: str):
	"""Leg 1 of the second factor: verify the password via core's own
	``authenticate`` primitive, then — for a passkey-enrolled user — return the
	passkey assertion challenge in core's ``verification``/``tmp_id`` envelope so
	the bundle's existing dispatch drives leg 2. Passkey-less users transparently
	fall back to core's OTP (``authenticate_for_2factor``); non-2FA users get a
	plain login (the LDAP finish).

	Active only when ``passkey_as_second_factor`` is on — **mode off ⇒ uniform
	``AuthenticationError`` before any authentication attempt**: direct-POST
	users simply face core's own path; a dormant parallel login endpoint would
	need core-parity maintained forever otherwise.

	Returns ``None`` and sets the envelope on ``frappe.local.response`` (core's
	own idiom — ``authenticate_for_2factor`` does the same), so ``verification``
	and ``tmp_id`` land at the JSON top level where the bundle reads them."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	from frappe.twofactor import authenticate_for_2factor, should_run_2fa

	settings = frappe.get_cached_doc("Passkey Settings")
	# enablement matrix: mode-off fails closed BEFORE any authentication.
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey second factor is not available."))

	# A raw db_set/console edit can leave passkey_as_second_factor=1 while
	# enable_two_factor_auth=0 (both validators bypassed) — the direct-POST floor
	# is then evaporated. Make it visible with a once-daily structured log.
	_observe_2fa_floor_desync(settings)

	# Core-parity checklist — a custom endpoint inherits NONE of login()'s
	# protections automatically.
	# 1. mirror `frappe/auth.py` login(): username/password login can be disabled.
	if frappe.get_system_settings("disable_user_pass_login"):
		raise frappe.AuthenticationError(_("Login with username and password is not allowed."))
	# 2. before_login parity — fire iff a hook is registered (v16/develop fire it
	#    in core login(); v15 never does, so there it is defense-in-depth).
	login_manager = _request_login_manager()
	if frappe.get_hooks("before_login"):
		login_manager.run_trigger("before_login")
	# 3. core authentication primitive: tracker accounting, uniform failures,
	#    Administrator handling — never reimplemented. Raises on bad credentials
	#    (→ uniform 401, "wrong password ⇒ no challenge").
	login_manager.authenticate(user=usr, pwd=pwd)
	user = login_manager.user
	# 4. forced-password-reset parity: mirror login()'s "Password Reset" branch so
	#    core's client handler redirects natively.
	if login_manager.force_user_to_reset_password():
		reset_doc = frappe.get_doc("User", user)
		frappe.local.response["redirect_to"] = reset_doc._reset_password(
			send_email=False, password_expired=True
		)
		frappe.local.response["message"] = "Password Reset"
		return None

	# 5. dispatch (priority order): passkey leg → core OTP → plain login.
	credentials = _enabled_credentials(user)
	# Administrator is hard-exempt from the passkey leg, matching core's own 2FA
	# exemption (`twofactor.py:114-115`).
	if credentials and user != "Administrator":
		_dispatch_passkey_second_factor(user, pwd, credentials, settings, should_run_2fa(user))
		return None
	if should_run_2fa(user):
		# No credential: hand off to core's OTP. `usr`/`pwd` MUST still be present
		# in `frappe.form_dict` — `cache_2fa_data` reads `pwd` from there
		# (`twofactor.py:94-96`); popping it first caches None and breaks core's
		# leg 2 for every passkey-less user (the confirmed bug). Core restores
		# the pair under its own `tmp_id`, so leg 2 completes with zero app
		# involvement on every branch.
		authenticate_for_2factor(user)
		return None
	# Neither passkey nor OTP: plain login (the LDAP finish). Flag it as an app
	# password login so seed_sudo_window classifies the window "password", not
	# "weak": this endpoint's path is NOT /api/method/login, so _classify_login_method's
	# core-path heuristic would otherwise mis-seed "weak" and the conditional-create
	# nudge would re-prompt seconds after a genuine password login.
	frappe.form_dict.pop("pwd", None)
	frappe.local.flags.passkey_login = False
	frappe.local.flags.passkeys_password_login = True
	_mint_session(user)
	return None


def _dispatch_passkey_second_factor(user, pwd, credentials, settings, run_2fa):
	"""Mint the leg-1 passkey ceremony + core-shaped envelope (dispatch).

	The binder cookie is set **iff-absent** with a sliding refresh HERE:
	``login_with_password`` is a cookie-touching endpoint precisely so this
	path never depends on a boot-time ``begin_login`` that may have 429'd or never
	run — without it leg 2 would 401 on a missing binder. ``pwd`` is retained in
	the state **only** when the user is OTP-capable AND fallback is allowed (the
	same conjunction that offers the fallback), so the knob gates retention
	server-side, not just the client."""
	from passkeys import engine

	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		raise frappe.AuthenticationError(_("Passkeys are not available on this host."))
	origins = policy.resolve_origins(settings, rp_id)
	_enforce_request_host(origins)

	allow_otp_fallback = bool(cint(settings.passkey_2fa_allow_otp_fallback))
	fallback = bool(run_2fa and allow_otp_fallback)

	binder_value = state.set_binder_cookie()  # set-iff-absent + sliding refresh
	allow_credentials = [
		{"id": row.credential_id, "transports": json.loads(row.transports or "[]")} for row in credentials
	]
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id,
		allow_credentials=allow_credentials,
		user_verification=policy.UV_WIRE["second_factor"],  # "discouraged"
	)
	state_id = state.store_ceremony(
		{
			"v": 1,
			"type": "second_factor",
			"user": user,
			"usr": user,  # restored into form_dict for the OTP fallback leg
			"pwd": pwd if fallback else None,  # retained only under the fallback conjunction
			"fallback": fallback,
			"attempts": 0,
			"challenge_b64": challenge_b64,
			"rp_id": rp_id,
			"origins": origins,
			"binder_sha256": state.binder_hash(binder_value),
			"allow_sha256": [row.credential_id_sha256 for row in credentials],
			"created_at": now_datetime().isoformat(),
		}
	)
	# Core's own two-request envelope (`twofactor.py:80-91` shape). Set on
	# frappe.local.response so `verification`/`tmp_id` are top-level JSON keys.
	frappe.local.response["verification"] = {
		"method": "Passkey",
		"setup": False,
		"options": options,
		"fallback": {"otp": fallback},
	}
	frappe.local.response["tmp_id"] = state_id


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=60)
def verify_second_factor(state_id: str, credential):
	"""Leg 2 of the second factor: verify the passkey assertion against the
	leg-1 ceremony, re-run core-equivalent re-authentication (a mid-ceremony
	password change or user-disable must NOT mint a session), then mint through
	the ``_mint_session`` choke point.

	A verify failure past the single-use consume **re-arms** a fresh state:
	the 401 body carries a fresh ``state_id`` + ``verification.options`` and
	the ``CeremonyExpired`` wire type, up to ``SECOND_FACTOR_MAX_ATTEMPTS`` — the
	bundle distinguishes "re-armed, retry" from "terminal, back to password" by
	the presence of those body keys. This keeps retry and OTP fallback alive
	without weakening single-use consume (a wrong passkey must not burn the only
	2FA state)."""
	refuse_if_core_native()  # dormant-shell (before the crypto engine import)
	from passkeys import engine

	credential = _as_dict(credential)

	# atomic single-use consume; a second-factor state can never be anything else
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "second_factor":
		raise CeremonyExpired(_("That took too long — please try again."))

	# binder cookie match (guest ceremony) + mode still enabled — structural
	# pre-verify checks; these do NOT re-arm (misconfig/attack, not a retry).
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	_enforce_request_host(record.get("origins") or [])

	# everything from credential membership onward burns the state on rejection,
	# so any failure here routes to the re-arm contract.
	try:
		cred, result = _verify_second_factor_assertion(record, credential, engine, settings)
	except frappe.AuthenticationError:
		# The user is resolved from leg 1 (record["user"]) — feed the tracker
		# before re-arming so a wrong leg-2 passkey feeds the same lockout as a bad
		# password, without disturbing the re-arm/uniform-401 wire contract.
		_track_verify_failure(record.get("user"))
		raise _rearm_second_factor(record)

	# core-leg-2-equivalent re-authentication BEFORE minting (fails closed;
	# no re-arm — a changed password / disabled user is terminal, not a retry).
	_reauthenticate_before_mint(record)

	# bookkeeping + the flip (password co-present ⇒ a UV=1 assertion may
	# initialize a uv_initialized=0 credential).
	_advance_credential(cred.name, result)
	if result.user_verified and not cint(cred.uv_initialized):
		frappe.db.set_value("WebAuthn Credential", cred.name, "uv_initialized", 1, update_modified=False)

	frappe.local.flags.passkey_login = True
	_mint_session(record["user"])
	return None


def _verify_second_factor_assertion(record, credential, engine, settings):
	"""Resolve + verify the leg-2 assertion: the credential MUST belong to
	``record.user`` AND be a member of THIS ceremony's ``allow_credentials`` (both
	halves — the StrongKey substitution class), then the assertion verifies
	against the record's challenge/origin/rp_id. Raises an ``AuthenticationError``
	subclass on any rejection (caller re-arms)."""
	cred_id = credential.get("id") or credential.get("rawId")
	if not cred_id:
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	sha = hashlib.sha256(_b64url_decode(cred_id)).hexdigest()
	# membership in the ceremony's own allow-list (identified second factor)
	if sha not in set(record.get("allow_sha256") or []):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	cred = frappe.db.get_value(
		"WebAuthn Credential",
		{"credential_id_sha256": sha},
		["name", "user", "enabled", "public_key", "sign_count", "backup_eligible", "uv_initialized"],
		as_dict=True,
	)
	if not cred or cred.user != record["user"] or not cint(cred.enabled):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	result = engine.verify_authentication(
		credential=credential,
		expected_challenge=record["challenge_b64"],
		expected_rp_id=record["rp_id"],
		expected_origin=record["origins"],
		credential_public_key=cred.public_key,
		stored_sign_count=cint(cred.sign_count),
		stored_backup_eligible=bool(cint(cred.backup_eligible)),
		require_user_verification=False,  # UV recorded, not required at leg 2
		sign_count_hard_fail=bool(cint(settings.passkey_sign_count_hard_fail)),
	)
	return cred, result


def _reauthenticate_before_mint(record) -> None:
	"""Core-leg-2-equivalent re-authentication. Core's own leg 2
	re-runs ``authenticate(user, pwd)`` with the cached pair, re-checking the
	password against the *current* hash and re-running the enabled check — so a
	mid-ceremony password change (the canonical compromise response) or an admin
	user-disable fails closed. We mirror it: the enabled check ALWAYS runs; when
	the state carries ``pwd`` (fallback conjunction), re-run core's
	``authenticate`` too (tracker accounting included, exact parity). When ``pwd``
	was not cached, the enabled re-check still runs and the ≤300 s password
	staleness residual is accepted and documented (the attacker must still hold
	the passkey)."""
	user = record["user"]
	if not cint(frappe.db.get_value("User", user, "enabled")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	pwd = record.get("pwd")
	if pwd:
		# re-check the password against the CURRENT hash (raises on a mid-ceremony
		# change) — the same primitive core's leg 2 uses.
		_request_login_manager().authenticate(user=user, pwd=pwd)


def _rearm_second_factor(record) -> Exception:
	"""Return the exception to raise on a leg-2 verify failure.

	Re-arm (attempts still under the cap): mint a FRESH ``second_factor`` state —
	new challenge + new TTL, same user/pwd/binder/fallback/allow-list — and put
	its ``state_id`` + fresh ``verification.options`` in the 401 body under the
	``CeremonyExpired`` wire type; the bundle's ``reArmedFrom`` reads exactly those
	keys and retries. Terminal (cap reached): a bare ``CeremonyExpired`` with NO
	fresh keys — the bundle finds no re-armed state and routes back to the password
	form. A genuine consume-miss (stale/replayed id) lands on the same terminal
	shape, which is correct."""
	from passkeys import engine

	attempts = cint(record.get("attempts")) + 1
	if attempts >= SECOND_FACTOR_MAX_ATTEMPTS:
		# terminal — no re-arm; back to the password form (uniform, non-enumerating)
		return CeremonyExpired(_("Passkey could not be verified. Please sign in again."))

	options, challenge_b64 = engine.build_authentication_options(
		rp_id=record["rp_id"],
		allow_credentials=_allow_from_record(record),
		user_verification=policy.UV_WIRE["second_factor"],
	)
	fresh_state_id = state.store_ceremony(
		{
			**record,
			"attempts": attempts,
			"challenge_b64": challenge_b64,
			"created_at": now_datetime().isoformat(),
		}
	)
	# re-arm wire keys: state_id + fresh options ride the JSON error body.
	frappe.local.response["state_id"] = fresh_state_id
	frappe.local.response["verification"] = {"method": "Passkey", "options": options}
	return CeremonyExpired(_("That passkey didn't work — please try again."))


def _allow_from_record(record) -> list:
	"""Rebuild the assertion ``allowCredentials`` for a re-armed ceremony from the
	credential ids the leg-1 ceremony pinned (still the user's enabled set)."""
	rows = frappe.get_all(
		"WebAuthn Credential",
		filters={"credential_id_sha256": ["in", record.get("allow_sha256") or []]},
		fields=["credential_id", "transports"],
	)
	return [{"id": r.credential_id, "transports": json.loads(r.transports or "[]")} for r in rows]


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=5, seconds=300)
def fallback_to_otp(state_id: str):
	"""Mid-flow OTP fallback: "Use a verification code instead". Offered
	only when leg 1 found the user OTP-capable AND ``passkey_2fa_allow_otp_fallback``
	is on. **Re-check the knob server-side and fail uniformly when off** — a
	phisher or tampered client must not downgrade a passkey holder to phishable
	OTP by calling this directly (regression). On success: restore ``usr``
	and the stored ``pwd`` into ``frappe.form_dict`` and hand off to core's own
	``authenticate_for_2factor`` — core's OTP UI and core's leg 2 then complete
	natively."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	from frappe.twofactor import authenticate_for_2factor

	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "second_factor":
		raise CeremonyExpired(_("That took too long — please try again."))
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	# server-side knob re-check: the state only carries `pwd` under the fallback
	# conjunction, but re-read the live knob too (defense against a stale state
	# minted before the admin turned the knob off).
	if not (cint(settings.passkey_2fa_allow_otp_fallback) and record.get("fallback") and record.get("pwd")):
		raise frappe.AuthenticationError(_("A verification code is not available for this sign-in."))

	# restore the credentials core's OTP leg needs (`cache_2fa_data` reads pwd
	# from form_dict; `get_cached_user_pass` restores the pair at leg 2).
	frappe.form_dict["usr"] = record.get("usr") or record["user"]
	frappe.form_dict["pwd"] = record["pwd"]
	_record_fallback_used(record["user"])
	authenticate_for_2factor(record["user"])
	return None


def _record_fallback_used(user: str) -> None:
	"""FIDO-downgrade telemetry: a passkey holder chose phishable
	OTP. Activity-Log-backed, plus an opt-in email under
	``passkey_notify_password_fallback`` (default off). Non-blocking."""
	from passkeys import notifications

	notifications.record_risk_event(
		notifications.RISK_FALLBACK_USED, user, f"OTP fallback taken by passkey holder {user}"
	)


def _enabled_credentials(user: str) -> list:
	"""The user's enabled credentials (id + sha + transports) for the leg-1
	allow-list. Empty ⇒ the user has no passkey second factor."""
	return frappe.get_all(
		"WebAuthn Credential",
		filters={"user": user, "enabled": 1},
		fields=["credential_id", "credential_id_sha256", "transports"],
	)


def _request_login_manager():
	"""The request-time ``LoginManager`` (core builds one per request), or a fresh
	one on the direct-call/unit path — mirrors :func:`_mint_session`'s bootstrap."""
	login_manager = getattr(frappe.local, "login_manager", None)
	if login_manager is None:
		from frappe.auth import LoginManager

		login_manager = LoginManager()
		frappe.local.login_manager = login_manager
	return login_manager


def _observe_2fa_floor_desync(settings) -> None:
	"""Once-daily structured log when the enforcement floor has evaporated at
	runtime: ``passkey_as_second_factor=1`` while core
	``enable_two_factor_auth=0`` — reachable only via a raw ``db_set``/console edit
	that bypasses both validators. Non-blocking."""
	try:
		if not cint(settings.passkey_as_second_factor):
			return
		if cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth")):
			return
		key = frappe.cache.make_key("passkeys:2fa_floor_desync_logged")
		if frappe.cache.get(key):
			return
		frappe.cache.set(key, "1", ex=86400)
		frappe.log_error(
			title="passkeys: 2FA floor desync",
			message=(
				"passkey_as_second_factor=1 but System Settings enable_two_factor_auth=0 — "
				"the direct-POST OTP backstop is evaporated. A password-only login bypasses "
				"the second factor for users not going through the passkey UI. Re-enable Two "
				"Factor Authentication, or disable Passkey as Second Factor."
			),
		)
	except Exception:
		pass


# ===========================================================================
# Guest translations endpoint — REQUIRED on v15/v16 (native guest i18n
# delivery is develop-only); the login bundle merges the catalog client-side.
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["GET"])
@rate_limit(limit=30, seconds=60)
def get_app_translations(version: str | None = None):
	"""Return the passkeys app's translation catalog for the request language.
	Wraps ``get_translations_from_apps`` scoped to this app only; the
	bundle fetches once, memoizes on the app-controlled ``version`` param, and
	``Object.assign``-merges into ``frappe._messages`` (never clobbers the
	Web-Form / core catalog). Without it, non-English v15/v16 sites see English
	passkey UI — a release blocker.

	Rate-limited like the sibling page-load-coupled guest endpoints (30/min/IP,
	as ``begin_login``); a ``version``-keyed long-lived Cache-Control lets the
	browser reuse the catalog until the client mints a new ``version`` (a new URL
	⇒ a cache miss), so this endpoint is normally hit once per catalog release."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	from frappe.translate import get_translations_from_apps

	lang = getattr(frappe.local, "lang", None) or "en"
	_set_translations_cache_control(version)
	return get_translations_from_apps(lang, apps=["passkeys"])


def _set_translations_cache_control(version) -> None:
	"""Caching: the catalog is content-addressed by the client's ``version``
	cache-buster (a new version ⇒ a new URL), so a versioned request is safely
	immutable-cacheable for a year; an unversioned request gets a short private
	cache. ``private`` (never ``public``) because the URL does not encode the
	language — a shared cache must not serve one language's catalog to another.
	Best-effort: a direct-call context without ``response_headers`` skips it."""
	headers = getattr(frappe.local, "response_headers", None)
	if headers is None:
		return
	if version:
		headers.set("Cache-Control", "private, max-age=31536000, immutable")
	else:
		headers.set("Cache-Control", "private, max-age=300")


# ===========================================================================
# Management-surface data endpoints — authed, webauthn-free
# ===========================================================================


@frappe.whitelist(methods=["POST"])
def get_signal_data():
	"""Data for the WebAuthn Signal API ``signalAllAcceptedCredentials``:
	the caller's own ``{rp_id, user_handle, credential_ids}`` (enabled credentials
	only). The desk/portal bundle fires the signal fire-and-forget in-session so a
	deleted credential is pruned from the browser's autofill list. Identity is
	strictly ``frappe.session.user``; no client param selects the account."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = _require_authed_user()
	state.rate_limit_user("get_signal_data", 60, 60)  # 60/min/user
	settings = frappe.get_cached_doc("Passkey Settings")
	rp_id = policy.resolve_rp_id(settings)
	handle = frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle")
	credential_ids = frappe.get_all(
		"WebAuthn Credential", filters={"user": user, "enabled": 1}, pluck="credential_id"
	)
	# name/display_name feed signalCurrentUserDetails (F2), keeping the provider's stored
	# account-chooser label in sync when the user later edits full_name/email. name mirrors
	# the WebAuthn userName set at registration (the login id); display_name the userDisplayName.
	full_name = frappe.db.get_value("User", user, "full_name") or user
	return {
		"rp_id": rp_id,
		"user_handle": handle,
		"credential_ids": credential_ids,
		"name": user,
		"display_name": full_name,
	}


@frappe.whitelist(methods=["POST"])
def record_nudge(event: str):
	"""Fold an enrollment-nudge event into the caller's server-side cadence state.
	``event`` ∈ {``shown``, ``declined``, ``opt_out``}. The
	counters are **server-side per-user** so a three-browser user gets N prompts
	total (not 3N); capability checks stay client-side."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = _require_authed_user()
	state.rate_limit_user("record_nudge", 30, 3600)  # 30/hr/user
	from passkeys import boot

	return {"nudge_state": boot.record_nudge_event(user, event)}


@frappe.whitelist(methods=["POST"])
def record_enforcement(event: str):
	"""Fold an enrollment-enforcement event into the caller's server-side grace state.
	``event`` ∈ {``defer``, ``incapable``}. ``defer`` ("Remind me later") spends one
	grace login; ``incapable`` records that the device cannot create a passkey and, when
	the site's Incapable Device Policy is ``Block + Notify Admin``, raises the admin
	advisory. The grace counter is **server-side per-user** so a multi-browser user has
	one shared grace budget; capability detection stays client-side."""
	refuse_if_core_native()  # dormant-shell: 417 the moment core is native
	user = _require_authed_user()
	state.rate_limit_user("record_enforcement", 30, 3600)  # 30/hr/user
	from passkeys import boot, notifications

	new_state = boot.record_enforcement_event(user, event)
	if event == "incapable" and _incapable_policy_is_block_notify():
		notifications.record_enforcement_incapable(user)
	return {"enforcement_state": new_state}


def _incapable_policy_is_block_notify() -> bool:
	return (
		frappe.db.get_single_value("Passkey Settings", "passkey_enforce_incapable") == "Block + Notify Admin"
	)


def _require_authed_user() -> str:
	user = frappe.session.user
	if not user or user in ("Guest", ""):
		raise frappe.AuthenticationError(_("Not permitted."))
	return user


# ---------------------------------------------------------------------------
# session mint (the one auditable choke point)
# ---------------------------------------------------------------------------


def _mint_session(user: str) -> None:
	"""Funnel every passkey session through ``login_as`` → ``post_login``
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
	bookkeeping after a successful assertion. A flagged
	sign-count regression is recorded but never blocks (unless hard-fail already
	raised inside the engine)."""
	values = {
		"sign_count": result.sign_count_to_store,
		"backup_state": int(result.backup_state),
		"last_used_at": now_datetime(),
		"last_used_ip": _request_ip(),
	}
	newly_flagged = _apply_sign_count_flag(name, bool(result.sign_count_regression), values)
	frappe.db.set_value("WebAuthn Credential", name, values, update_modified=False)
	_notify_if_newly_flagged(name, newly_flagged)


def _apply_sign_count_flag(name: str, regression: bool, values: dict) -> bool:
	"""Fold a sign-count regression into a pending credential-write ``values`` dict
	and report whether this is the unflagged→flagged rising edge. Shared by
	:func:`_advance_credential` and the uv-setup completion (SEC-2) so both advance
	sites flag identically — the uv-setup login leg was the SOLE advance for its
	assertion yet dropped the flag entirely before this factoring."""
	if not regression:
		return False
	values["flagged"] = 1
	values["flagged_reason"] = "sign_count_regression"
	return not cint(frappe.db.get_value("WebAuthn Credential", name, "flagged"))


def _notify_if_newly_flagged(name: str, newly_flagged: bool) -> None:
	"""Fire the out-of-band "passkey flagged" notice on the unflagged→flagged
	edge only (a repeatedly-regressing credential does not re-spam the owner)."""
	if not newly_flagged:
		return
	from passkeys import notifications

	row = frappe.db.get_value("WebAuthn Credential", name, ["user", "label"], as_dict=True)
	if row:
		notifications.notify_credential_flagged(row.user, row.label, "sign_count_regression")


def _track_verify_failure(user: str | None) -> None:
	"""Feed frappe's ``LoginAttemptTracker`` on a passkey verify FAILURE for a
	RESOLVED user: a passkey brute-force must
	feed the same consecutive-failure lockout counter as a failed password login —
	core's ``LoginManager.authenticate`` calls the identical ``add_failure_attempt``
	on a bad password. ``raise_locked_exception=False``: the counter is fed but the
	lock is never *raised here*, so the wire answer stays the uniform 401 and never
	leaks that this user exists / is locked out. Called only where a user is
	actually resolved (a pre-resolution failure has no user to track). Best-effort —
	a tracker failure must never turn a 401 into a 500."""
	if not user:
		return
	try:
		from frappe.auth import get_login_attempt_tracker

		tracker = get_login_attempt_tracker(user, raise_locked_exception=False)
		if tracker:
			tracker.add_failure_attempt()
	except Exception:
		frappe.log_error(title="passkeys: login-failure tracking failed")


# ---------------------------------------------------------------------------
# guest-ceremony helpers
# ---------------------------------------------------------------------------


def _enforce_request_host(origins: list) -> None:
	"""Fail-closed host membership. No-ops without an HTTP request
	(direct-call unit paths) — the library's ``expected_origin`` check against
	clientDataJSON is the binding enforcement; this is the ops-diagnosable
	pre-check that also powers the begin-side uniform 401."""
	origin = _request_origin()
	if origin is None:
		return
	if origin not in origins:
		# One structured log on EVERY host-mismatch refusal. Previously
		# only the registration path logged; begin_login / begin_confirmation / the
		# verify legs (which route here, and via confirm.py's delegating shim) were
		# silent. The ``origins`` list leads with ``https://<rp_id>`` (the configured
		# RP ID). Ops-diagnosable; the wire answer stays the uniform 401.
		frappe.log_error(
			title="passkeys: request host not in configured origins",
			message=f"request origin {origin} not in {origins}",
		)
		raise frappe.AuthenticationError(_("Passkeys are not available on this host."))


def _request_origin() -> str | None:
	request = getattr(frappe.local, "request", None)
	headers = getattr(request, "headers", None) if request is not None else None
	return headers.get("Origin") if headers is not None else None


def _request_ip() -> str | None:
	return getattr(frappe.local, "request_ip", None)


def _b64url_decode(value: str) -> bytes:
	"""Base64url-decode a credential id (tolerating stripped padding). A malformed
	value raises the uniform ``AuthenticationError`` — never a raw
	``binascii.Error`` / ``ValueError`` / ``TypeError`` (C5): those would escape as
	a 500, breaking the uniform-401 contract. Critically, in
	``verify_second_factor`` this call runs AFTER the single-use state consume,
	inside a ``try`` that catches only ``AuthenticationError`` — so a raw exception
	would burn the 2FA state with NO re-arm; raising ``AuthenticationError`` here
	routes a garbage id through the existing re-arm path instead."""
	import binascii

	try:
		return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
	except (binascii.Error, ValueError, TypeError) as exc:
		raise frappe.AuthenticationError(_("Passkey could not be verified.")) from exc


def _as_dict(value):
	import json

	return json.loads(value) if isinstance(value, str) else value
