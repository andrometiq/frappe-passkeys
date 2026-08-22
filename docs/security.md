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

This uniform-error contract assumes **System Settings → Allow Error Traceback** is off. Frappe v15
ships it defaulted on; production sites must disable it or every 401 includes the traceback.

**Guest login-CSRF defence (binder cookie).** Because the attacker in a login-CSRF
is the ceremony's own legitimate starter, a browser-bound token is the only
defence. Guest ceremonies set an ephemeral `Secure; HttpOnly; SameSite=Lax`
cookie and store only its SHA-256 in the record; verify fails closed unless the
request carries the matching cookie. An attacker cannot set or read this HttpOnly
cookie cross-site. Authenticated ceremonies bind to the session id instead.

**Origin and RP-ID pinning, exact-match, fail-closed.** RP ID and origins are
resolved once at enable time from pinned configuration — never from live `Host`
or `X-Forwarded-*` headers. Origins are an exact-match allowlist including port;
the library checks the assertion's origin against that list. A compatible `host_name` contributes
its own exact origin and explicit Passkey Origins add to it; RP ID alone never authorizes
`https://<rp_id>`, and an empty resolved web-origin set is invalid. iOS must therefore have its
asserted `https://<rp_id>` origin explicitly present when the site's `host_name` does not contribute
that exact value. The request host is re-checked at both begin and complete.

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

**Second-factor enforcement covers alternate login paths.** When Passkey as Second Factor is on and
a user has an enabled credential, the final `on_login` hook vetoes password, email-link,
social/OAuth, LDAP, and other core login completions unless this app has completed the passkey step.
The only downgrade is an enabled OTP fallback initiated by this app: `fallback_to_otp` issues a
short-lived, one-time marker bound to core's `tmp_id`, and the hook consumes it only on core's login
route after core accepts a non-empty OTP. Carrying that `tmp_id` on an email-link or OAuth request
does not consume or satisfy it. Calling core's OTP path directly creates no marker and remains blocked.

**Administrator exemption is narrow.** Administrator remains break-glass exempt from the per-user
*Passkey Only Login* veto. Administrator is **not** exempt from the enrolled second-factor rule:
once an enabled credential is explicitly enrolled while Passkey as Second Factor is active, the
same alternate-path veto applies. Core's site-wide `disable_user_pass_login` also has no
Administrator exemption. Passkey enrollment enforcement likewise keeps `System Manager` users in
scope by default; recovery uses a temporary per-user marker role or the operator-only console helper,
never a standing administrator-role exemption.

**Password rotation is checked at the session boundary.** Every password-to-passkey ceremony stores
a keyed, non-reversible version of the password hash at leg one and compares it with the current
version before minting a session. A password change during the ceremony fails closed. The marker
does not expose the password hash. The plaintext password rides the Redis ceremony record (TTL 300 s)
on the second-factor leg only when `passkey_2fa_allow_otp_fallback=1` (the default) and the user is
OTP-capable, matching core's `cache_2fa_data`, or for an external-auth user without a local password
hash because core must re-authenticate it before session minting. Mode enablement and local-password
ceremonies fail closed when the site has no `encryption_key`.

**Password-reset keys rotate a password but do not satisfy a passkey factor.** Frappe core calls
`login_as` after a successful reset. For an enrolled second-factor user, the app lets the reset
transaction finish but downgrades that automatic login to Guest; the user must then sign in with the
new password and passkey (or an explicitly enabled OTP fallback). Passkey-only accounts keep their
stricter veto.

**Passkey failures share core's consecutive-login tracker.** Once a credential resolves an account,
invalid assertions feed Frappe's tracker. A locked account cannot bypass that lock with a valid
passkey, and a successful verified passkey resets the same consecutive-failure state.

**Action-confirmation grants are tightly bound.** A grant from the
`@passkey_protected` primitive is single-use, ~180 s, and bound to
`user + session + action + exact payload`. Tokens are returned once and stored
only as SHA-256, so a cache snapshot yields nothing usable. The grant is consumed
*before* the protected function runs (one gesture = one attempt), and the payload
hash is always computed server-side with a pinned canonicalization — the client
never computes a hash. The action↔challenge binding replaces the retired
`txAuthSimple` extension: the signature commits to a challenge that names exactly
one action and payload.

The decorator publishes its static policy to site-scoped Redis before returning the initial 401, so
`begin_confirmation` and password re-auth can land on another worker without changing the offered
methods or display metadata. Unknown actions fail closed without a password fallback; the protected
method's consumer remains the final method and payload authority.

**The "sudo" re-auth window** (default 600 s) gates the app's own management
surface (add/delete passkeys). It is seeded by a fresh interactive login or a
password / passkey re-auth. A "weak" login (email link, social) seeds only the
restricted first-passkey bootstrap when passwordless passkey login is enabled, never general
management power.

**Security invariants are transactionally locked.** Authentication locks the user and credential
before counter/UV updates; registration locks the user, handle, and credential census before cap
enforcement and insertion; credential deletion and passkey-only toggles share a locked login-floor
census; and mode-setting changes lock the Single rows before checking passkey-only users. This
prevents concurrent workers from committing individually valid reads into an invalid combined state.

**Enrollment grace is once per session.** A user/session digest is claimed atomically in Redis, so
retries or multiple tabs can consume at most one grace defer for that session.

**Uninstall exports fail closed.** Credential export schema v2 is site-bound and authenticated with
HMAC-SHA256 derived from the site's `encryption_key`, written atomically at mode `0600`. Import
rejects another site or a bad signature. Its default requires empty passkey tables;
`allow_existing=True` is an explicit reviewed merge with row-level rejection reporting. Unsigned
schema-v1 files from pre-v2 app builds are rejected unless an operator reviews their provenance and
passes `allow_unsigned_legacy=True`; this opt-in does not make the file authenticated.

**Native dormancy requires an explicit contract.** Fresh installation is blocked by any
`frappe.passkey` module to avoid installing two authorities. An already-installed app no-ops hooks
and returns `417 PasskeyServedByCore` only when core defines the exact marker
`FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`. Module presence alone is not
accepted as evidence of a complete or safe handover.

**Password-oracle throttling** on the password-taking endpoints the app adds
beyond core's login surface (the uv-setup step and the confirmation password
fallback): a per-user failure counter locks after 5 failures for 15 minutes,
independent of core's login tracker. The primary login leg keeps core's own
protections only, to avoid an account-lockout denial of service.

**Rate limits, keyed two ways.** Pre-session (guest) endpoints keep core's own
`@rate_limit` decorator, which keys on **IP** — the only stable identity before a
session exists. Every authenticated endpoint instead uses a **per-user** app
counter (a session-user-keyed cache token), because core's IP keying would 429 a
whole NAT'd office off one busy user and can't attribute abuse to an account. A
guest ceremony can never reach the per-user endpoints, so the two classes don't
overlap.

*Guest / pre-session endpoints — core `@rate_limit`, IP-keyed:*

| Endpoint | Limit |
|---|---|
| `begin_login` | 30 / 60 s |
| `verify_login` | 10 / 60 s |
| `complete_uv_setup` | 5 / 300 s |
| `login_with_password` | 10 / 60 s |
| `verify_second_factor` | 10 / 60 s |
| `fallback_to_otp` | 5 / 300 s |
| `get_app_translations` | 30 / 60 s |
| `assetlinks` / `apple_app_site_association` | 120 / 60 s |

*Authenticated endpoints — per-user app counter, keyed on the session user:*

| Endpoint | Limit |
|---|---|
| `begin_registration` | 20 / hour |
| `verify_registration` | 20 / hour |
| `list_credentials` | 60 / min |
| `rename_credential` | 20 / hour |
| `delete_credential` | 10 / hour |
| `get_signal_data` | 60 / min |
| `record_nudge` | 30 / hour |
| `record_enforcement` | 30 / hour |
| `begin_confirmation` | 30 / 5 min |
| `verify_confirmation` | 30 / 5 min |
| `reauth_password` | 5 / 5 min |
| `get_resolved_rp_id` | 30 / min |
| `get_security_posture` | 30 / min |
| `get_user_enforcement_admin` | 60 / min |
| `set_user_exemption` | 30 / hour |
| `reset_enforcement_grace` | 30 / hour |

The action-confirmation endpoints (`begin_confirmation` / `verify_confirmation` /
`reauth_password`) require an authenticated caller, so they sit in the per-user
class — the `reauth_password` 5 / 5 min ceiling is a second, coarse backstop on
top of the per-user password-oracle lock above.

The last five rows are the Passkey Settings / enforcement-admin endpoints. They
carry the per-user counter **and** an additional `System Manager` role gate (the
settings and enforcement-admin surfaces are admin-only). Three are read-only;
`set_user_exemption` and `reset_enforcement_grace` are the exceptions — both
*mutate authorization state* (the first grants or revokes a user's exemption from
passkey-enrollment enforcement via the dedicated exempt role; the second clears a
user's enforcement grace-login state), which is why both carry the tighter
30 / hour ceiling.

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
- **Alternate first factors are incompatible with second-factor-only enrollment.** The final veto
  blocks social/OAuth, LDAP, and email-link completions for an enrolled user because those core
  paths cannot enter this app's passkey leg. Keep passwordless "Login with Passkey" enabled for
  enrolled accounts that do not have a usable local password, or retain an operator recovery path.
- **First-passkey enrollment can ride a weak first factor (bootstrap).** With
  `passkey_allow_first_enrollment_on_weak_login` on (default), a session established
  through a weak first factor — an email login link or social/OAuth sign-in — may
  enroll the account's **first** passkey without a stronger re-auth. This solves the
  chicken-and-egg where a passwordless account has nothing stronger to authorize its
  first credential. The carve-out is deliberately narrow: it applies only while
  first-factor "Login with Passkey" is on, only to a user with **zero** enabled
  credentials (every later add still needs a passkey- or password-seeded sudo
  window), and every use records a `passkeys:weak_login_enrollment` risk event
  ([`operations.md`](operations.md)). Turn off
  `passkey_allow_first_enrollment_on_weak_login` to require a stronger factor for the
  first enrollment too.
- **A same-session password change does not revoke an already-live management sudo window**
  (≤600 s). Password+passkey login ceremonies are different: they compare the keyed password-hash
  version before session minting and fail if it changed.
- **A backup restored to a stale point resurrects revoked credentials** — review
  credential inventories after any restore ([`operations.md`](operations.md)).
- **The guest binder cookie is not `__Host-` scoped.** It is `Secure; HttpOnly;
  SameSite=Lax` but carries no `__Host-` prefix, so a sibling subdomain of the site's
  registrable domain (a compromised or attacker-controlled `*.example.com`) could plant a
  `passkey_binder` cookie the browser also sends here — cookie fixation. This does not defeat
  the login-CSRF defence: the cookie is HttpOnly and the ceremony matches its stored SHA-256, so
  an attacker who cannot read the victim's value cannot complete a ceremony bound to it, and
  Frappe core's own session `sid` cookie shares the identical exposure. The `__Host-` prefix
  would close it but requires an HTTPS scheme the app cannot assume — it is silently dropped on
  `http://` origins (dev benches, CI), which would fail login closed.
- **Cross-origin / multi-domain serving** (Related Origin Requests) and
  identifier-first login are not implemented in this version.
- **A console-created settings desync** (e.g. passkey 2FA on while core 2FA off)
  is outside what validators can catch; the app surfaces it with a once-daily log
  line rather than silently.
- **Enrollment "Enforce" is a post-login interstitial, not an authentication
  block.** The session already exists before the enforce gate runs — it raises
  friction toward enrolling a passkey (and, once grace is spent, becomes a
  non-dismissible interstitial), but it does not turn passkeys into a server-side
  first-factor requirement. A client that never renders the app's JS is not gated
  by it. Enforce drives adoption; it is the login modes (passkey first-factor /
  second-factor) that decide what actually authenticates a session.

- **The Frappe version floor is enforced at install time only.** The app requires Frappe
  ≥15.108.0 / ≥16.18.3 (closing CVE-2026-47194, host-header poisoning of magic/passwordless login
  links) and refuses a fresh install below it, but the check does not re-run on `bench update` /
  `migrate`. The app's final login veto already covers enrolled users on the modes it protects; the
  residual exposure is the broader login surface (e.g. email-link login for non-enrolled users), so
  keep the deployment's Frappe patched operationally, not only at first install.
- **Attacker-reachable transitive parsers float without a lockfile.** Client attestation is CBOR-
  decoded (`cbor2`) and attestation certificate chains are ASN.1-parsed (`pyasn1`); both arrive
  transitively via `webauthn` and the repo pins only `webauthn==2.8.0`. A fresh resolve is patched
  (`cbor2>=5.9.0`, `pyasn1>=0.6.4`), but a stale bench may carry an older, vulnerable version — run
  `bench setup requirements` and confirm those minimums on the deployment bench. The app's own
  `cryptography` posture inherits Frappe's pin (currently `~=50`); re-check it when Frappe's moves.

## Reporting a vulnerability

Follow [`../SECURITY.md`](../SECURITY.md). Do not include vulnerability details in a public issue.
Issues independently affecting Frappe core should also follow Frappe's own current responsible-
disclosure process; this app's upstream proposal does not make the projects one security boundary.
