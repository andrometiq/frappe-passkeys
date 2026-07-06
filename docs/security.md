# Security model (operator's view)

What this app enforces, what it trusts, and what residual risk remains. This is a
deployment-level description, not the internal design record.

## What the app enforces

**The whole ceremony is server-side and browser-bound.** Challenges are
CSPRNG-generated, stored server-side, and matched against exactly one server
record scoped to a single ceremony type — a login challenge can never satisfy a
registration or a confirmation. The challenge TTL tracks the client timeout
(≈300 s for login/registration, 180 s for action confirmation).

**Single-use challenges, fail-closed.** Each ceremony state is consumed
atomically on the first verify attempt (exactly one caller wins across workers).
A consumed, expired, or evicted state yields a uniform typed error, never a
silent pass. A wrong passkey at the second factor re-arms a *fresh* state up to a
small cap rather than burning the only 2FA state.

**Guest login-CSRF defence (binder cookie).** Because the attacker in a login-CSRF
is the ceremony's own legitimate starter, a browser-bound token is the only
defence. Guest ceremonies set an ephemeral `Secure; HttpOnly; SameSite=Lax`
cookie and store only its SHA-256 in the record; verify fails closed unless the
request carries the matching cookie. An attacker cannot set or read this HttpOnly
cookie cross-site. Authenticated ceremonies bind to the session id instead.

**Origin and RP-ID pinning, exact-match, fail-closed.** RP ID and origins are
resolved once at enable time from pinned configuration — never from live `Host`
or `X-Forwarded-*` headers. Origins are an exact-match allowlist including port;
the library checks the assertion's origin against that list. The request host is
re-checked at both begin and complete.

**Cross-origin rejection is enforced by the app.** `py_webauthn` 2.8 accepts
`crossOrigin: true` and never parses `topOrigin`, so the app parses the raw
client data itself and refuses any cross-origin ceremony. This is the sole
enforcement of the "no cross-origin iframe ceremonies" rule.

**User-verification policy, per ceremony.** A passwordless first-factor login
completes only when the authenticator actually verified the user (UV bit set)
**and** that credential's UV was initialized with a second factor — a bare UV
assertion against an uninitialized credential is routed to a one-time
password-backed setup step, never straight to a session. Action confirmation
always requires UV. UV is read from the assertion, never assumed.

**Sign-count and backup-flag policy.** Counters are stored and checked app-side:
an exact non-zero replay is always rejected; a regression is flagged (and its
owner emailed) or hard-rejected under the *Hard-fail* knob; the counter is never
written downward. Backup-eligibility is write-once at registration — a later
mismatch fails the ceremony.

**Global credential uniqueness.** `credential_id_sha256` is a unique index;
duplicate registration and cross-account credential hijack both fail closed at
insert.

**Session minting through one choke point.** Every passkey session is created via
core's `login_as` → `post_login` — full login hooks, IP/hour checks, a fresh
session and CSRF token, and an Activity Log row. The app never spins up a fresh
login manager mid-flow.

**Action-confirmation grants are tightly bound.** A grant from the
`@passkey_protected` primitive is single-use, ~180 s, and bound to
`user + session + action + exact payload`. Tokens are returned once and stored
only as SHA-256, so a cache snapshot yields nothing usable. The grant is consumed
*before* the protected function runs (one gesture = one attempt), and the payload
hash is always computed server-side with a pinned canonicalization — the client
never computes a hash. The action↔challenge binding replaces the retired
`txAuthSimple` extension: the signature commits to a challenge that names exactly
one action and payload.

**The "sudo" re-auth window** (default 600 s) gates the app's own management
surface (add/delete passkeys). It is seeded by a fresh interactive login or a
password / passkey re-auth. A "weak" login (email link, social) seeds only the
restricted first-passkey bootstrap, never general management power.

**Password-oracle throttling** on the password-taking endpoints the app adds
beyond core's login surface (the uv-setup step and the confirmation password
fallback): a per-user failure counter locks after 5 failures for 15 minutes,
independent of core's login tracker. The primary login leg keeps core's own
protections only, to avoid an account-lockout denial of service.

**Rate limits** on the guest and confirmation endpoints:

| Endpoint | Limit |
|---|---|
| `begin_login` | 30 / 60 s |
| `verify_login` | 10 / 60 s |
| `complete_uv_setup` | 5 / 300 s |
| `login_with_password` | 10 / 60 s |
| `verify_second_factor` | 10 / 60 s |
| `fallback_to_otp` | 5 / 300 s |
| `begin_confirmation` | 30 / 300 s |
| `verify_confirmation` | 30 / 300 s |
| `reauth_password` | 5 / 300 s |

**No account enumeration.** First-factor login is discoverable-only — it takes no
identifier, so the begin response leaks nothing about which accounts have
passkeys. Ownership checks on management endpoints return a uniform "not found"
so one user cannot probe another's credentials.

## What the app trusts

- **The deployment terminates HTTPS at the public host and forwards the real
  origin.** The app pins RP ID and origins to that host; if the proxy lies about
  the host, ceremonies fail closed rather than misbind, but correct operation
  assumes the public host is the RP ID. HTTPS/HSTS at the edge is the operator's
  responsibility (origins refuse plain `http` except localhost in developer mode).
- **No untrusted content is served within the RP ID's scope.** A passkey is
  scoped to the RP ID; hosting attacker-controlled content on a subdomain within
  that scope is a deployment concern the app cannot enforce.
- **`bench console` / raw DB writes are site-admin authority** and bypass every
  validation guard here, by design (see [`operations.md`](operations.md)). This
  is out of the threat model and is what makes lockouts recoverable.
- **Core's own primitives** — password checking, the login tracker, session and
  CSRF handling, and the OTP second factor — are used as-is, never reimplemented.

## Residual risks

- **RP ID is a one-way door.** Changing it invalidates every enrolled passkey.
  This is inherent to WebAuthn, not a bug; plan re-enrollment.
- **Recovery is part of the boundary.** An account's assurance is only as strong
  as its weakest fallback. Keep recovery flows at parity-or-stronger friction than
  the passkey itself; the account-recovery story is admin-mediated
  re-enrollment, not a weaker alternate login. Encourage users to enroll **two**
  passkeys.
- **A same-session password change does not revoke a live sudo window** (≤600 s) —
  accepted, because the password change itself is a sudo-seeding factor.
- **A backup restored to a stale point resurrects revoked credentials** — review
  credential inventories after any restore ([`operations.md`](operations.md)).
- **Cross-origin / multi-domain serving** (Related Origin Requests) and
  identifier-first login are not implemented in this version.
- **A console-created settings desync** (e.g. passkey 2FA on while core 2FA off)
  is outside what validators can catch; the app surfaces it with a once-daily log
  line rather than silently.

## Reporting a vulnerability

Please report security issues privately to the maintainers rather than opening a
public issue, and allow time for a fix before any disclosure. Because this app is
intended for upstream Frappe, follow the Frappe project's responsible-disclosure
process for issues that also affect core.
