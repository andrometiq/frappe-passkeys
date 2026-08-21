# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Ceremony / sudo / grant / uv-setup state store (folds into
``frappe/passkey.py``).

Every single-use ``passkeys:*`` key uses **only raw ``redis.Redis`` operations
on the made key** (``frappe.cache`` *is* a ``redis.Redis``). The wrapper's
``set_value``/``get_value``/``delete_value`` are banned for these keys:
``set_value`` pickles, ``delete_value`` discards the delete count, and
``get_value`` serves a request-local copy that is provably stale after a
remote consume (PROBE-bench). Values are JSON, never pickle. Redis
``ex`` is the sole expiry authority — records never re-derive expiry from
their own timestamps with the consuming worker's clock.
"""

import hashlib
import json

import frappe
import redis

# TTLs are code constants, not knobs (fixed policy); the sudo window is
# the one settings-driven lifetime (`passkey_reauth_window`, later phase).
CEREMONY_TTL = 300
CONFIRM_CEREMONY_TTL = 180
UV_SETUP_TTL = 180
GRANT_TTL = 180
OTP_FALLBACK_TTL = CEREMONY_TTL
PASSWORD_FAILURE_TTL = 900
PASSWORD_FAILURE_LIMIT = 5
SECOND_FACTOR_MAX_ATTEMPTS = 3
ENFORCEMENT_DEFER_TTL = 30 * 24 * 60 * 60

CEREMONY_PREFIX = "passkeys:ceremony:"
SUDO_PREFIX = "passkeys:sudo:"
GRANT_PREFIX = "passkeys:grant:"
UV_SETUP_PREFIX = "passkeys:uvsetup:"
OTP_FALLBACK_PREFIX = "passkeys:otp-fallback:"
PASSWORD_FAILURE_PREFIX = "passkeys:pwfail:"
RATE_LIMIT_PREFIX = "passkeys:ratelimit:"
ENFORCEMENT_DEFER_PREFIX = "passkeys:enforcement-defer:"

# Guest-ceremony browser binder. Ephemeral cookie; the ceremony record
# stores only sha256(value). Cover the initial second-factor state plus every
# re-armed state before the terminal attempt.
BINDER_COOKIE = "__Host-passkey_binder"
BINDER_MAX_AGE = SECOND_FACTOR_MAX_ATTEMPTS * CEREMONY_TTL


def new_id() -> str:
	"""Server-issued, unguessable id (CSPRNG) — never keyed by user or challenge."""
	return frappe.generate_hash()


# ---------------------------------------------------------------------------
# single-use records (atomic consume)
# ---------------------------------------------------------------------------


def store_ceremony(record: dict, ttl: int = CEREMONY_TTL) -> str:
	state_id = new_id()
	_put_json(CEREMONY_PREFIX + state_id, record, ttl)
	return state_id


def consume_ceremony(state_id: str) -> dict | None:
	"""Atomically fetch-and-invalidate; exactly one caller wins across workers.

	Returns ``None`` when the record was consumed, expired, evicted, or never
	existed — callers MUST fail closed (typed ``CeremonyExpired``)."""
	return _consume_json(CEREMONY_PREFIX + state_id)


def store_uv_setup(record: dict, ttl: int = UV_SETUP_TTL) -> str:
	setup_id = new_id()
	_put_json(UV_SETUP_PREFIX + setup_id, record, ttl)
	return setup_id


def consume_uv_setup(setup_id: str) -> dict | None:
	return _consume_json(UV_SETUP_PREFIX + setup_id)


def get_uv_setup(setup_id: str) -> dict | None:
	"""Read a UV setup without consuming it.

	Wrong password attempts remain retryable (subject to the password throttle);
	the record is atomically consumed only after a correct password.
	"""
	raw = frappe.cache.get(_make_key(UV_SETUP_PREFIX + setup_id))
	return json.loads(raw) if raw is not None else None


def store_otp_fallback(tmp_id: str, record: dict, ttl: int = OTP_FALLBACK_TTL) -> None:
	"""Authorize exactly one core-OTP completion initiated by this app.

	Core's public login endpoint can otherwise complete OTP directly and bypass the
	passkey second-factor route. The marker is keyed by core's own ``tmp_id`` and is
	consumed by the final ``on_login`` hook only after core has accepted the OTP.
	"""
	_put_json(OTP_FALLBACK_PREFIX + tmp_id, record, ttl)


def consume_otp_fallback(tmp_id: str) -> dict | None:
	return _consume_json(OTP_FALLBACK_PREFIX + tmp_id)


def store_grant(token_hash: str, record: dict, ttl: int = GRANT_TTL) -> None:
	"""Keyed by sha256(token) — only the hash is ever stored."""
	_put_json(GRANT_PREFIX + token_hash, record, ttl)


def consume_grant(token_hash: str) -> dict | None:
	return _consume_json(GRANT_PREFIX + token_hash)


# ---------------------------------------------------------------------------
# reusable records (sudo window; same raw treatment uniformly)
# ---------------------------------------------------------------------------


def set_sudo_window(sid: str, record: dict, ttl: int) -> None:
	_put_json(SUDO_PREFIX + sid, record, ttl)


def get_sudo_window(sid: str) -> dict | None:
	raw = frappe.cache.get(_make_key(SUDO_PREFIX + sid))
	return json.loads(raw) if raw is not None else None


def clear_sudo_window(sid: str) -> None:
	frappe.cache.delete(_make_key(SUDO_PREFIX + sid))


# ---------------------------------------------------------------------------
# counters (pwfail + per-user rate shapes; TTL guaranteed at creation)
# ---------------------------------------------------------------------------


def bump_counter(name: str, ttl: int) -> int:
	"""Pinned idiom: ``SET key 0 EX ttl NX`` + ``INCR`` in one pipeline — a
	worker dying between a naive INCR and EXPIRE would leave an immortal
	counter. Eviction resetting a counter is accepted: throttles fail open."""
	key = _make_key(name)
	pipe = frappe.cache.pipeline()
	pipe.set(key, 0, ex=ttl, nx=True)
	pipe.incr(key)
	return pipe.execute()[1]


def get_counter(name: str) -> int:
	raw = frappe.cache.get(_make_key(name))
	return int(raw) if raw is not None else 0


def clear_counter(name: str) -> None:
	frappe.cache.delete(_make_key(name))


def record_password_failure(user: str) -> int:
	return bump_counter(PASSWORD_FAILURE_PREFIX + user, PASSWORD_FAILURE_TTL)


def claim_password_attempt(user: str) -> int:
	return bump_counter(PASSWORD_FAILURE_PREFIX + user, PASSWORD_FAILURE_TTL)


def is_password_throttled(user: str) -> bool:
	return get_counter(PASSWORD_FAILURE_PREFIX + user) >= PASSWORD_FAILURE_LIMIT


def clear_password_failures(user: str) -> None:
	clear_counter(PASSWORD_FAILURE_PREFIX + user)


def claim_enforcement_defer(user: str, sid: str) -> bool:
	"""Return true once per user/session, atomically across workers."""
	digest = hashlib.sha256(f"{user}\x00{sid}".encode()).hexdigest()
	return bool(
		frappe.cache.set(
			_make_key(ENFORCEMENT_DEFER_PREFIX + digest),
			b"1",
			ex=ENFORCEMENT_DEFER_TTL,
			nx=True,
		)
	)


def rate_limit_user(name: str, limit: int, ttl: int) -> None:
	"""Per-user rate limit for the authenticated endpoints. Core
	``@rate_limit`` cannot key on ``frappe.session.user`` — it keys on IP and/or a
	spoofable ``form_dict`` field (``frappe/rate_limiter.py:142``), which 429s a
	NAT'd campus and is forgeable — so the app owns a cache counter keyed on the
	session user (one per ``(endpoint, user)``), sharing :func:`bump_counter`'s
	TTL-at-creation guarantee. The ``limit``-th call in the window passes;
	the next raises the 429 wire contract. Eviction resets the counter — the
	throttle fails open, exactly like the password-failure counter."""
	user = frappe.session.user or "Guest"
	if bump_counter(f"{RATE_LIMIT_PREFIX}{name}:{user}", ttl) > limit:
		raise frappe.TooManyRequestsError(frappe._("You've hit the rate limit. Please try again shortly."))


# ---------------------------------------------------------------------------
# guest browser binder cookie (the login-CSRF defence)
# ---------------------------------------------------------------------------


def read_binder_cookie() -> str | None:
	"""The binder value carried on the current request, or ``None``."""
	request = getattr(frappe.local, "request", None)
	if request is None:
		return None
	cookies = getattr(request, "cookies", None)
	if cookies is None:
		return None
	return cookies.get(BINDER_COOKIE) or None


def set_binder_cookie() -> str | None:
	"""Set-iff-absent + sliding refresh: reuse the request's existing
	binder value if present, else mint one; (re)send it with a fresh Max-Age.
	Returns the value whose sha256 the ceremony record should store, or ``None``
	when there is no cookie manager (no HTTP context) — the caller then stores a
	``None`` binder hash and every ``verify_*`` fails closed."""
	manager = getattr(frappe.local, "cookie_manager", None)
	if manager is None:
		return None
	value = read_binder_cookie() or frappe.generate_hash()
	# Backport: re-verify v16/develop CookieManager still injects Path=/ and no
	# Domain; both are required by the __Host- prefix.
	manager.set_cookie(
		BINDER_COOKIE,
		value,
		httponly=True,
		samesite="Lax",
		secure=True,
		max_age=BINDER_MAX_AGE,
	)
	return value


def binder_hash(value: str | None) -> str | None:
	return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else None


def binder_matches(stored_hash: str | None) -> bool:
	"""Fail-closed match: the request must carry a binder cookie whose
	sha256 equals the value stored at begin time. A missing stored hash (record
	minted without a cookie manager) or a missing/mismatched request cookie both
	return ``False`` — an attacker cannot set or read this HttpOnly cookie
	cross-site, which is the structural login-CSRF defence."""
	if not stored_hash:
		return False
	got = read_binder_cookie()
	return bool(got) and binder_hash(got) == stored_hash


# ---------------------------------------------------------------------------
# raw idioms (normative)
# ---------------------------------------------------------------------------


def _make_key(name: str) -> bytes:
	# site-scoped structurally: b"<db_name>|<name>"
	return frappe.cache.make_key(name)


def _put_json(name: str, record: dict, ttl: int) -> None:
	# TTL at write; JSON; never touches frappe.local.cache
	frappe.cache.set(_make_key(name), json.dumps(record), ex=ttl)


def _consume_json(name: str) -> dict | None:
	key = _make_key(name)
	try:
		raw = frappe.cache.getdel(key)  # Redis >= 6.2
	except redis.exceptions.ResponseError:
		raw = _consume_via_pipeline(key)
	return json.loads(raw) if raw is not None else None


def _consume_via_pipeline(key: bytes) -> bytes | None:
	"""MULTI/EXEC fallback for Redis < 6.2: proceed iff the value was present
	AND this caller's DELETE removed it (delete count == 1)."""
	pipe = frappe.cache.pipeline()
	pipe.get(key)
	pipe.delete(key)
	raw, deleted = pipe.execute()
	if raw is None or not deleted:
		return None
	return raw
