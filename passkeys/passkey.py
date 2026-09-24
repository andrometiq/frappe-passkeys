# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted login endpoints (folds into ``frappe/passkey.py`` on the core merge):
passwordless login, the uv-setup step-up, the password + passkey second factor, the
guest translations catalog, the management data endpoints, and the User cascade.

``webauthn`` (via ``passkeys.engine``) is imported lazily inside the ceremony
endpoint bodies, so a broken crypto wheel never reaches import time."""

import hashlib
import hmac

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import cint, now_datetime

from passkeys import boot, ceremony, install, policy, session, state
from passkeys.errors import CeremonyExpired, UnknownCredential, UVSetupRequired, refuse_if_core_native


def cascade_delete_user_artifacts(doc, method=None):
	"""User on_trash: drop the user's credential, handle, and Defaults rows. A dormant
	shell leaves the cascade to core, and never raises (that would block User deletion)."""
	if install.dormant():
		return
	for doctype in ("WebAuthn Credential", "WebAuthn User Handle"):
		frappe.db.delete(doctype, {"user": doc.name})
	boot.clear_user_state(doc.name)


def refuse_enrolled_user_merge(doc, method=None, old=None, new=None, merge=False):
	"""User before_rename: a merge would re-point both users' handle rows at one user and
	fail on the handle's unique index; refuse it with a clear message instead."""
	if install.dormant():
		return
	if merge and frappe.db.count("WebAuthn User Handle", {"user": ("in", [old, new])}) > 1:
		frappe.throw(
			_(
				"Cannot merge {0} into {1}: both users have passkeys. Delete the passkeys and the WebAuthn User Handle of {0} first."
			).format(old, new),
			frappe.ValidationError,
		)


def rename_user_artifacts(doc, method=None, old=None, new=None, merge=False):
	"""User after_rename: carry Defaults state forward; merges preserve target values."""
	if install.dormant() or not old or not new or old == new:
		return
	boot.rename_user_state(old, new, merge)


# ===========================================================================
# First-factor passwordless login
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=30, seconds=60)
def begin_login():
	"""Mint discoverable-credential assertion options + a single-use ceremony and set the
	guest binder cookie. No identifier is taken (no credential-broadcast or enumeration
	oracle). Always answers with the mode flags, the bundle's only config channel;
	``state_id`` + ``options`` + the cookie only when ``login_with_passkey`` is on."""
	refuse_if_core_native()
	settings = frappe.get_cached_doc("Passkey Settings")
	first_factor = bool(cint(settings.login_with_passkey))
	second_factor = bool(cint(settings.passkey_as_second_factor))
	response = {
		"enabled": first_factor or second_factor,
		"modes": {"first_factor": first_factor, "second_factor": second_factor},
	}
	if not first_factor:
		return response

	from passkeys import engine

	rp_id, origins = _require_rp(settings)
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id, user_verification=policy.UV_WIRE["first_factor"]
	)
	binder_value = state.set_binder_cookie()
	response["state_id"] = state.store_ceremony(
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
	response["options"] = options
	return response


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=10, seconds=60)
def verify_login(state_id: str, credential: object):
	"""Verify a discoverable assertion, resolve the account from its ``userHandle`` +
	credential id, enforce the UV outcome policy, and mint a session.

	Success returns ``None`` so core's login envelope (``message``, ``home_page``) set by
	``login_as`` stays at the top level; the client redirects via ``home_page`` only."""
	refuse_if_core_native()
	from passkeys import engine

	credential = ceremony.require_credential_dict(credential, _("Passkey could not be verified."))

	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "login":
		raise CeremonyExpired(_("That took too long — please try again."))
	# binder cookie must match the value bound at begin (login-CSRF defence)
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.login_with_passkey):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	ceremony.enforce_request_host(record.get("origins") or [])

	cred = _lock_discoverable_credential(credential)
	_require_login_attempt_allowed(cred.user)

	# A verification failure past credential resolution feeds core's LoginAttemptTracker,
	# so a passkey brute-force shares the password lockout; the wire stays a uniform 401.
	# UV_SETUP is a legitimate step-up, not a failure.
	hard_fail = bool(cint(settings.passkey_sign_count_hard_fail))
	try:
		result = engine.verify_stored_assertion(credential, record, cred, sign_count_hard_fail=hard_fail)
		# passwordless ONLY on UV=1 ∧ uv_initialized=1
		outcome = policy.passwordless_uv_outcome(result.user_verified, bool(cint(cred.uv_initialized)))
		if outcome == policy.UV_REJECT:
			raise frappe.AuthenticationError(
				_("This passkey can't complete a passwordless sign-in. Please verify another way.")
			)
	except frappe.AuthenticationError as exc:
		_track_verify_failure(cred.user)
		raise frappe.AuthenticationError(_("Passkey could not be verified.")) from exc
	_track_verify_success(cred.user)

	if outcome == policy.UV_SETUP:
		# This leg does not advance the credential; complete_uv_setup reclassifies the
		# counter against the locked row.
		frappe.local.response["setup_id"] = state.store_uv_setup(
			{
				"v": 1,
				"user": cred.user,
				"credential": cred.name,
				"binder_sha256": record.get("binder_sha256"),
				"new_sign_count": result.new_sign_count,
				"backup_state": int(result.backup_state),
			}
		)
		raise UVSetupRequired(_("One more step to finish setting up this passkey."))

	ceremony.advance_credential(cred.name, result, sign_count_hard_fail=hard_fail)
	frappe.local.response["authenticator_attachment"] = credential.get("authenticatorAttachment")
	# before login_as: the passkey_only veto exemption and the "passkey" sudo-window class
	frappe.local.flags.passkey_login = True
	_mint_session(cred.user)
	return None


def _lock_discoverable_credential(credential: dict):
	"""Resolve the account from ``userHandle`` + credential id and lock User then
	Credential. ``userHandle`` is required for discoverable login; a truly unknown id is
	``UnknownCredential`` (safe pre-auth Signal feed), every ownership mismatch uniform."""
	user_handle = credential["response"].get("userHandle")
	credential_id = credential.get("id") or credential.get("rawId")
	if not isinstance(user_handle, str) or not user_handle or not credential_id:
		raise UnknownCredential(_("Passkey could not be verified."))
	credential_sha256 = ceremony.credential_id_sha256(credential)
	# Unlocked reads only choose the User row that starts the global lock order.
	handle_user = ceremony.get_handle_user(user_handle)
	candidate_user = frappe.db.get_value(
		"WebAuthn Credential", {"credential_id_sha256": credential_sha256}, "user"
	)
	if not candidate_user:
		raise UnknownCredential(_("Passkey could not be verified."))
	if not ceremony.lock_enabled_user(handle_user or candidate_user):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	locked_handle_user = ceremony.get_handle_user(user_handle, for_update=True)
	cred = ceremony.lock_credential(credential_sha256)
	if not cred:
		raise UnknownCredential(_("Passkey could not be verified."))
	if (
		not locked_handle_user
		or locked_handle_user != handle_user
		or cred.user != handle_user
		or not cint(cred.enabled)
	):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	return cred


# ===========================================================================
# uv-setup step-up — the uv_initialized repair (guest)
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=5, seconds=300)
def complete_uv_setup(setup_id: str, pwd: str):
	"""Authorize the ``uv_initialized`` false→true flip with a one-time password check.
	The setup record was minted only by a verified UV=1 assertion, so possession + UV are
	proven; this adds the knowledge factor L3 §7.2 requires for the flip. Stays available
	under core ``disable_user_pass_login``: the password is a factor for the flip, not a
	password login."""
	refuse_if_core_native()
	from frappe.utils.password import check_password

	record = state.get_uv_setup(setup_id)
	if not record:
		raise CeremonyExpired(_("That took too long — please try again."))
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.login_with_passkey):  # before any attempt is spent
		raise frappe.AuthenticationError(_("Passkey could not be verified."))

	user = record["user"]
	_require_login_attempt_allowed(user)
	# Claim atomically before checking the password: the limit-th attempt passes;
	# the next is refused without touching the oracle.
	if state.claim_password_attempt(user) > state.PASSWORD_FAILURE_LIMIT:
		raise frappe.AuthenticationError(_("Too many attempts. Please try again later."))
	try:
		check_password(user, pwd)
	except frappe.AuthenticationError:
		_track_verify_failure(user)
		raise frappe.AuthenticationError(_("That password didn't match — try again."))
	state.clear_password_failures(user)

	# Consume only after the password is valid: exactly one concurrent correct completion
	# wins; failed password attempts can retry the same short-lived setup.
	if state.consume_uv_setup(setup_id) != record:
		raise CeremonyExpired(_("That took too long — please try again."))

	# User before Credential, both locks held through the mutation and session mint.
	if not ceremony.lock_enabled_user(user):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	cred = frappe.db.get_value(
		"WebAuthn Credential", record["credential"], ["user", "enabled"], as_dict=True, for_update=True
	)
	if not cred or cred.user != user or not cint(cred.enabled):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	# A concurrent completion of the same assertion reclassifies as an equal-nonzero replay.
	ceremony.advance_credential(
		record["credential"],
		frappe._dict(new_sign_count=record["new_sign_count"], backup_state=record["backup_state"]),
		sign_count_hard_fail=bool(cint(settings.passkey_sign_count_hard_fail)),
		values={"uv_initialized": 1},
	)

	# a passkey_only_login user repairing a credential must not trip their own veto
	frappe.local.flags.passkey_login = True
	_mint_session(user)
	return None


# ===========================================================================
# Second factor (password → passkey step-up), in core's `verification` + `tmp_id`
# envelope. The login bundle pins these method paths.
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=10, seconds=60)
def login_with_password(usr: str, pwd: str):
	"""Leg 1: verify the password with core's ``authenticate``; an enrolled user gets the
	passkey challenge in core's ``verification``/``tmp_id`` envelope, a passkey-less 2FA
	user falls back to core's OTP, anyone else gets a plain login.

	Mode off ⇒ uniform ``AuthenticationError`` before any authentication attempt. Returns
	``None``; the envelope rides ``frappe.local.response`` (core's own idiom)."""
	refuse_if_core_native()
	from frappe.twofactor import authenticate_for_2factor, should_run_2fa

	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey second factor is not available."))

	# Core-parity: a custom endpoint inherits none of login()'s protections.
	if frappe.get_system_settings("disable_user_pass_login"):
		raise frappe.AuthenticationError(_("Password sign-in is turned off for this site."))
	login_manager = _request_login_manager()
	# v16/develop fire before_login in core login(); v15 never does.
	if frappe.get_hooks("before_login"):
		login_manager.run_trigger("before_login")
	# tracker accounting, uniform failures, Administrator handling — never reimplemented
	login_manager.authenticate(user=usr, pwd=pwd)
	user = login_manager.user
	if login_manager.force_user_to_reset_password():
		reset_doc = frappe.get_doc("User", user)
		frappe.local.response["redirect_to"] = reset_doc._reset_password(
			send_email=False, password_expired=True
		)
		frappe.local.response["message"] = "Password Reset"
		return None

	credentials = ceremony.enabled_credentials(user)
	if credentials:
		_dispatch_passkey_second_factor(user, pwd, credentials, settings, should_run_2fa(user))
		return None
	if should_run_2fa(user):
		# `usr`/`pwd` must still be in form_dict: core's cache_2fa_data reads pwd there.
		authenticate_for_2factor(user)
		return None
	# Plain login. The flag makes seed_sudo_window classify it "password": this path is not
	# /api/method/login, so the core-path heuristic would otherwise seed "weak".
	frappe.form_dict.pop("pwd", None)
	frappe.local.flags.passkey_login = False
	frappe.local.flags.passkeys_password_login = True
	_mint_session(user)
	return None


def _dispatch_passkey_second_factor(user, pwd, credentials, settings, run_2fa):
	"""Mint the leg-1 passkey ceremony and core-shaped envelope. Sets the binder cookie
	here, so leg 2 never depends on a boot-time ``begin_login``. ``pwd`` is kept only for
	the OTP fallback, or when an external-auth user has no local password hash to version."""
	from passkeys import engine

	rp_id, origins = _require_rp(settings)
	fallback = bool(run_2fa and cint(settings.passkey_2fa_allow_otp_fallback))
	password_version = _password_version(user)
	binder_value = state.set_binder_cookie()
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=rp_id,
		allow_credentials=ceremony.credential_descriptors(credentials),
		user_verification=policy.UV_WIRE["second_factor"],
	)
	state_id = state.store_ceremony(
		{
			"v": 1,
			"type": "second_factor",
			"user": user,
			"pwd": pwd if fallback or password_version is None else None,
			"password_version": password_version,
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
	frappe.local.response["verification"] = {
		"method": "Passkey",
		"setup": False,
		"options": options,
		"fallback": {"otp": fallback},
	}
	frappe.local.response["tmp_id"] = state_id


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=10, seconds=60)
def verify_second_factor(state_id: str, credential: object):
	"""Leg 2: verify the assertion against the leg-1 ceremony, re-authenticate like core's
	leg 2 (a password change or user disable mid-ceremony mints nothing), then mint.

	A verification failure past the consume re-arms a fresh state, up to
	``state.SECOND_FACTOR_MAX_ATTEMPTS``: the 401 body carries a new ``state_id`` +
	``verification.options`` under the ``CeremonyExpired`` type, and the bundle tells
	"retry" from "back to password" by those keys. A wrong passkey never burns the only
	2FA state."""
	refuse_if_core_native()
	from passkeys import engine

	credential = ceremony.require_credential_dict(credential, _("Passkey could not be verified."))
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "second_factor":
		raise CeremonyExpired(_("That took too long — please try again."))
	# structural checks — misconfiguration or attack, not a retry, so no re-arm
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	ceremony.enforce_request_host(record.get("origins") or [])
	user = record["user"]
	_require_login_attempt_allowed(user)

	hard_fail = bool(cint(settings.passkey_sign_count_hard_fail))
	try:
		cred = ceremony.lock_allowed_credential(record, credential, user)
		result = engine.verify_stored_assertion(credential, record, cred, sign_count_hard_fail=hard_fail)
	except frappe.AuthenticationError:
		_track_verify_failure(user)
		raise _rearm_second_factor(record)
	_track_verify_success(user)

	# terminal, not a retry: a changed password or disabled user
	_reauthenticate_before_mint(record)
	# password co-present ⇒ a UV=1 assertion initializes a uv_initialized=0 credential
	ceremony.advance_credential(
		cred.name,
		result,
		sign_count_hard_fail=hard_fail,
		values={"uv_initialized": 1} if result.user_verified else None,
	)
	frappe.local.flags.passkey_login = True
	_mint_session(user)
	return None


def _reauthenticate_before_mint(record) -> None:
	"""Core's leg 2 re-runs ``authenticate(user, pwd)``; compare the non-reversible
	password-hash version captured at leg 1 instead, plus the enabled check. When the state
	carries ``pwd`` for the OTP fallback, core's ``authenticate`` runs too, for tracker parity."""
	user = record["user"]
	if not cint(frappe.db.get_value("User", user, "enabled")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	if record.get("password_version") != _password_version(user):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	if record.get("pwd"):
		_request_login_manager().authenticate(user=user, pwd=record["pwd"])


def _rearm_second_factor(record) -> Exception:
	"""The exception for a leg-2 verification failure. Under the cap: a fresh
	``second_factor`` state (new challenge + TTL, same user/binder/allow-list) whose
	``state_id`` + options ride the 401 body. At the cap, or on a stale id: a bare
	``CeremonyExpired`` with no fresh keys — the bundle returns to the password form."""
	from passkeys import engine

	attempts = cint(record.get("attempts")) + 1
	if attempts >= state.SECOND_FACTOR_MAX_ATTEMPTS:
		return CeremonyExpired(_("Passkey could not be verified. Please sign in again."))

	rows = frappe.get_all(
		"WebAuthn Credential",
		filters={"credential_id_sha256": ["in", record.get("allow_sha256") or []]},
		fields=["credential_id", "transports"],
	)
	options, challenge_b64 = engine.build_authentication_options(
		rp_id=record["rp_id"],
		allow_credentials=ceremony.credential_descriptors(rows),
		user_verification=policy.UV_WIRE["second_factor"],
	)
	frappe.local.response["state_id"] = state.store_ceremony(
		{
			**record,
			"attempts": attempts,
			"challenge_b64": challenge_b64,
			"created_at": now_datetime().isoformat(),
		}
	)
	frappe.local.response["verification"] = {"method": "Passkey", "options": options}
	return CeremonyExpired(_("That passkey didn't work — please try again."))


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=5, seconds=300)
def fallback_to_otp(state_id: str):
	""" "Use a verification code instead": hand the leg-1 state to core's OTP flow. The
	knob is re-checked server-side, so a tampered client cannot downgrade a passkey holder
	to phishable OTP by calling this directly."""
	refuse_if_core_native()
	from frappe.twofactor import authenticate_for_2factor

	from passkeys import notifications

	settings = frappe.get_cached_doc("Passkey Settings")
	if not cint(settings.passkey_as_second_factor):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	record = state.consume_ceremony(state_id)
	if not record or record.get("type") != "second_factor":
		raise CeremonyExpired(_("That took too long — please try again."))
	if not state.binder_matches(record.get("binder_sha256")):
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	# live knob too: a state minted before an admin turned it off must not fall back
	if not (cint(settings.passkey_2fa_allow_otp_fallback) and record.get("fallback") and record.get("pwd")):
		raise frappe.AuthenticationError(_("A verification code is not available for this sign-in."))

	user = record["user"]
	# core's cache_2fa_data reads usr/pwd from form_dict
	frappe.form_dict["usr"] = user
	frappe.form_dict["pwd"] = record["pwd"]
	notifications.record_risk_event(
		notifications.RISK_FALLBACK_USED, user, f"OTP fallback taken by passkey holder {user}"
	)
	authenticate_for_2factor(user)
	core_tmp_id = frappe.local.response.get("tmp_id")
	if not core_tmp_id:
		raise frappe.AuthenticationError(_("A verification code could not be started for this sign-in."))
	state.store_otp_fallback(
		str(core_tmp_id), {"v": 1, "user": user, "created_at": now_datetime().isoformat()}
	)
	return None


def _password_version(user: str) -> str | None:
	"""A keyed, non-reversible version marker of the user's current password hash, so
	leg 2 detects a rotation without retaining the password. ``None`` for external-auth
	users without a local ``__Auth`` row."""
	password_hash = frappe.db.get_value(
		"__Auth",
		{"doctype": "User", "name": user, "fieldname": "password", "encrypted": 0},
		"password",
		order_by=None,
	)
	if not password_hash:
		return None
	key = frappe.conf.get("encryption_key")
	if not key:
		raise frappe.AuthenticationError(
			_("Passkeys require this site's encryption key. Contact your administrator.")
		)
	message = b"frappe-passkeys:password-version:v1\x00" + str(password_hash).encode("utf-8")
	return hmac.new(str(key).encode("utf-8"), message, hashlib.sha256).hexdigest()


def _request_login_manager():
	"""The request's ``LoginManager``, or a fresh one on the direct-call path."""
	login_manager = getattr(frappe.local, "login_manager", None)
	if login_manager is None:
		from frappe.auth import LoginManager

		login_manager = LoginManager()
		frappe.local.login_manager = login_manager
	return login_manager


def _require_rp(settings) -> tuple[str, list]:
	"""The RP ID and expected origins for a guest ceremony; fail closed when unconfigured
	or when the request host is not a configured origin."""
	rp_id = policy.resolve_rp_id(settings)
	if not rp_id:
		raise frappe.AuthenticationError(_("Passkeys aren't set up for this site."))
	origins = policy.resolve_expected_origins(settings, rp_id)
	ceremony.enforce_request_host(origins)
	return rp_id, origins


# ===========================================================================
# Guest translations — required on v15/v16 (native guest i18n is develop-only)
# ===========================================================================


@frappe.whitelist(allow_guest=True, methods=["GET"])  # nosemgrep: guest-whitelisted-method
@rate_limit(limit=30, seconds=60)
def get_app_translations():
	"""This app's translation catalog for the request language. The language is not in
	the URL, so the response is never cacheable."""
	refuse_if_core_native()
	from frappe.translate import get_translations_from_apps, get_user_translations

	# Frappe v15 has no response_headers; the client also fetches with no-store.
	headers = getattr(frappe.local, "response_headers", None)
	if headers is not None:
		headers.set("Cache-Control", "private, no-store")
	lang = getattr(frappe.local, "lang", None) or "en"
	# Site Translation rows let an operator add a language without a shipped CSV.
	return {**get_translations_from_apps(lang, apps=["passkeys"]), **get_user_translations(lang)}


# ===========================================================================
# Management-surface data endpoints — authed, webauthn-free
# ===========================================================================


@frappe.whitelist(methods=["POST"])
def get_signal_data():
	"""The caller's own ``{rp_id, user_handle, credential_ids, name, display_name}`` for
	the WebAuthn Signal API (``signalAllAcceptedCredentials`` /
	``signalCurrentUserDetails``), so the browser prunes deleted credentials and keeps
	the account label current. Identity is ``frappe.session.user`` only."""
	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("get_signal_data", 60, 60)
	return {
		"rp_id": policy.resolve_rp_id(frappe.get_cached_doc("Passkey Settings")),
		"user_handle": frappe.db.get_value("WebAuthn User Handle", {"user": user}, "handle"),
		"credential_ids": frappe.get_all(
			"WebAuthn Credential", filters={"user": user, "enabled": 1}, pluck="credential_id"
		),
		"name": user,
		"display_name": frappe.db.get_value("User", user, "full_name") or user,
	}


@frappe.whitelist(methods=["POST"])
def record_nudge(event: str):
	"""Fold an enrollment-nudge event (``shown`` / ``declined`` / ``opt_out``) into the
	caller's server-side cadence state, shared across their browsers."""
	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("record_nudge", 30, 3600)
	return {"nudge_state": boot.record_nudge_event(user, event)}


@frappe.whitelist(methods=["POST"])
def record_enforcement(event: str):
	"""Fold an enforcement event into the caller's server-side grace state. ``defer``
	("Remind me later") spends one grace login, once per session; ``incapable`` (the device
	cannot create a passkey) alerts the admins under ``Block + Notify Admin``."""
	refuse_if_core_native()
	user = session.require_authed_user()
	state.rate_limit_user("record_enforcement", 30, 3600)
	from passkeys import notifications

	if event not in boot.ENFORCE_EVENTS:
		frappe.throw(_("Unknown enforcement event."), frappe.ValidationError)
	settings = frappe.get_cached_doc("Passkey Settings")
	credential_count = frappe.db.count("WebAuthn Credential", {"user": user, "enabled": 1})
	verdict = boot.build_enforcement(user, settings, credential_count)
	if (
		event == "defer"
		and verdict["reason"] == "grace"
		and state.claim_enforcement_defer(user, frappe.session.sid)
	):
		return {"enforcement_state": boot.record_enforcement_defer(user)}
	if (
		event == "incapable"
		and verdict["reason"] in ("grace", "blocking")
		and verdict["incapable_policy"] == "block_notify"
	):
		notifications.record_enforcement_incapable(user)
	return {"enforcement_state": boot.get_enforcement_state(user)}


# ---------------------------------------------------------------------------
# session mint + login-attempt tracking
# ---------------------------------------------------------------------------


def _mint_session(user: str) -> None:
	"""The one session choke point: ``login_as`` → ``post_login`` runs every core login
	hook and check. The caller sets ``frappe.local.flags.passkey_login`` first."""
	_request_login_manager().login_as(user)


def _require_login_attempt_allowed(user: str) -> None:
	"""Apply core's consecutive-failure lock without exposing a distinct wire error."""
	try:
		from frappe.auth import get_login_attempt_tracker

		get_login_attempt_tracker(user)
	except frappe.SecurityException:
		raise frappe.AuthenticationError(_("Passkey could not be verified."))
	except Exception:
		frappe.log_error(title="passkeys: login-lock check failed")
		raise frappe.AuthenticationError(_("Passkey could not be verified."))


def _track_verify_failure(user: str) -> None:
	"""Feed core's ``LoginAttemptTracker`` like a bad password does. The lock is never
	raised here, so the wire stays the uniform 401; a tracker error never becomes a 500."""
	try:
		from frappe.auth import get_login_attempt_tracker

		tracker = get_login_attempt_tracker(user, raise_locked_exception=False)
		if tracker:
			tracker.add_failure_attempt()
	except Exception:
		frappe.log_error(title="passkeys: login-failure tracking failed")


def _track_verify_success(user: str) -> None:
	"""A verified passkey resets the consecutive-failure state it feeds."""
	try:
		from frappe.auth import get_login_attempt_tracker

		tracker = get_login_attempt_tracker(user, raise_locked_exception=False)
		if tracker:
			tracker.add_success_attempt()
	except Exception:
		frappe.log_error(title="passkeys: login-success tracking failed")
