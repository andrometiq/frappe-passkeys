# REST API reference

For integrators with **no JavaScript asset** — a native mobile app or a separate
single-page app. Every operation performed by the shipped UI and the
[headless JS API](custom-ui.md) goes through these whitelisted endpoints; this
page is the raw contract.

If you *can* load a script, prefer [`custom-ui.md`](custom-ui.md) — the headless API
handles the base64url encoding, the L3 JSON shapes, CSRF, and the retry contracts for
you. Read [`security.md`](security.md) and the [invariants](custom-ui.md#security-invariants-an-integrator-must-not-break)
before you build; a native app additionally needs [`mobile-apps.md`](mobile-apps.md).

---

## Conventions

- **URL**: `POST /api/method/<dotted.path>` (one endpoint is a `GET`, noted inline).
- **Body**: JSON. WebAuthn `credential` payloads follow the WebAuthn **Level 3
  JSON** shapes (`PublicKeyCredential.toJSON()` /
  `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`); `challenge`,
  `id`/`rawId`, `user.id`, `userHandle`, `signature`, etc. are **base64url**.
- **Success envelope**: Frappe wraps a whitelisted dict return as
  `{"message": <payload>}`. Login endpoints that mint a session instead return the
  core login envelope at the top level (`message: "Logged In"`, `home_page`).
- **Typed errors**: a refusal carries `exc_type` (the exception class name — match on
  **that**, never on message text) plus, for the 401 retry contracts, structured keys
  at the **top level** of the body. Codes: `CeremonyExpired` (401),
  `UnknownCredential` (401), `UVSetupRequired` (401), `PasskeyConfirmationRequired`
  (401), `PasskeyServedByCore` (417 — the app has stood down for native core).
- **Auth / CSRF**: authenticated endpoints need a logged-in session **and**
  `X-Frappe-CSRF-Token: <frappe.csrf_token>` on the POST. Guest login endpoints are
  CSRF-exempt but bound to an `HttpOnly` `passkey_binder` cookie the server sets on
  `begin_login` and checks on every `verify_*` — run the whole ceremony in one
  first-party browser/client context so the cookie rides along.
- **Interactive authenticator required**: these are ceremony transport endpoints, not a
  server-to-server authentication API. A client must drive a platform, roaming, or cross-device
  WebAuthn authenticator and preserve the first-party cookie/session context.
- **Rate limits**: guest ceremonies are IP-limited (core `@rate_limit`); authenticated
  ones are per-user. Both are listed per endpoint; exceeding one returns `429`.
- **Dormant shell**: endpoints return `417 PasskeyServedByCore` only when
  `frappe.passkey` advertises the exact handover marker
  `FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`. Mere module presence blocks
  fresh installation but does not make an installed app dormant.

---

## Guest — first-factor (passwordless) login

The ceremony is discoverable-credential only: **no username is ever sent**, so there
is no account-enumeration oracle. `begin_login` → `navigator.credentials.get()` on
the client → `verify_login`.

### `passkeys.passkey.begin_login`

Mint assertion options + a single-use ceremony and set the binder cookie. Always
answers `200` (it is also the client's config channel). `state_id`/`options` are
present **only** when `login_with_passkey` is on.
Source: `passkeys/passkey.py:begin_login`. Rate limit: **30 / 60 s / IP**. Guest.

- **Args**: none.
- **Success** `200`:
  ```json
  {
    "message": {
      "enabled": true,
      "modes": { "first_factor": true, "second_factor": false },
      "state_id": "<opaque>",
      "options": { "challenge": "<b64url>", "rpId": "example.com",
                   "userVerification": "preferred", "allowCredentials": [], "timeout": 60000 }
    }
  }
  ```
  Mode off ⇒ the same body without `state_id`/`options`. Sets `Set-Cookie:
  passkey_binder=…; HttpOnly`.
- **Errors**: `417` served-by-core; `AuthenticationError` if a mode is on but no RP ID
  resolves (fail-closed).

### `passkeys.passkey.verify_login`

Verify the assertion, resolve the account from its `userHandle` + credential id,
enforce the user-verification policy, mint the session.
Source: `passkeys/passkey.py:verify_login`. Rate limit: **10 / 60 s / IP**. Guest.

- **Args**: `state_id` (string), `credential` (the `PublicKeyCredential.toJSON()`
  assertion — a JSON object, or a JSON string).
- **Success** `200`: the core login envelope at top level — `message: "Logged In"`,
  `home_page: "/app"` (navigate there or reload); the session cookie is set.
- **Errors** (all `401`, match on `exc_type`):
  - `CeremonyExpired` — the `state_id` was consumed/expired. Call `begin_login` again
    and run a **fresh** `get()` (never re-POST the same assertion).
  - `UnknownCredential` — the assertion references no live credential (removed/stale).
  - `UVSetupRequired` — a UV=1 assertion against a credential that has not completed
    user-verification setup; the body carries a top-level `setup_id`. Continue with
    `complete_uv_setup`.
  - `AuthenticationError` — uniform failure (bad assertion, disabled account, wrong
    host, …). No detail is given by design.

### `passkeys.passkey.complete_uv_setup`

Finish a passkey whose `UVSetupRequired` was raised: a one-time password check
authorises the user-verification flip, then the session is minted. Stays available
even under `disable_user_pass_login` (the password is a factor for the flip, not a
password *login*). Source: `passkeys/passkey.py:complete_uv_setup`.
Rate limit: **5 / 300 s / IP**. Guest.

- **Args**: `setup_id` (from the `UVSetupRequired` body), `pwd` (string).
- **Success** `200`: the core login envelope (session minted).
- **Errors**: `CeremonyExpired` (401); `AuthenticationError` (401, incl. wrong
  password — throttled at 5 / 900 s / user).

---

## Guest — passkey as a second factor

Active only when `passkey_as_second_factor` is on. Password first (leg 1), passkey
step-up second (leg 2), speaking Frappe's own two-factor envelope so core paints the
result natively. These mirror a lot of core's `login()` / `authenticate_for_2factor`;
integrate them only if you are replacing the login page wholesale.

### `passkeys.passkey.login_with_password`

Leg 1: verify the password via core `authenticate`, then return a passkey assertion
challenge inside core's `verification` / `tmp_id` envelope (or transparently fall back
to core OTP / plain login for passkey-less users). Source:
`passkeys/passkey.py:login_with_password`. Rate limit: **10 / 60 s / IP**. Guest.

- **Args**: `usr` (string), `pwd` (string).
- **Success** `200`: sets `verification` + `tmp_id` at the top level (core's 2FA
  idiom). When `verification.method == "Passkey"`, `verification.options` is the
  assertion request and `verification.fallback.otp` says whether a one-time-code
  fallback is offered; otherwise it is core's OTP/SMS/Email envelope, or a plain
  `"Logged In"`.
- **Errors**: `AuthenticationError` (401, incl. mode-off and bad password — uniform,
  "wrong password ⇒ no challenge").

### `passkeys.passkey.verify_second_factor`

Leg 2: verify the step-up assertion, re-authenticate, mint the session. Source:
`passkeys/passkey.py:verify_second_factor`. Rate limit: **10 / 60 s / IP**. Guest.

- **Args**: `state_id` (the leg-1 `tmp_id`), `credential` (assertion JSON).
- **Success** `200`: the core login envelope (session minted).
- **Errors**: on a recoverable failure the `401 CeremonyExpired` body **re-arms** —
  it carries a fresh `state_id` + `verification.options` (retry up to 3×); their
  absence means terminal (restart at the app's password form; use OTP only through the offered
  `fallback_to_otp` flow).

The password leg records a keyed, non-reversible password-hash version and leg 2 compares it again
before minting the session. Password rotation or user disable during the ceremony is terminal and
fails closed. For enrolled users, the final login hook also vetoes alternate/core login paths unless
this app completed the passkey leg or issued the one-time OTP fallback marker.

### `passkeys.passkey.fallback_to_otp`

Abandon the passkey step-up mid-flow and hand off to core's one-time-code path
(re-checks the knob server-side). Source: `passkeys/passkey.py:fallback_to_otp`.
Rate limit: **5 / 300 s / IP**. Guest.

- **Args**: `state_id`.
- **Success** `200`: core's OTP envelope (`verification.method` OTP/SMS/Email).
  The handoff stores a short-lived marker bound to core's `tmp_id`; the final login hook consumes it
  once after core accepts the OTP. A direct core OTP flow has no marker and is vetoed for an enrolled
  second-factor user.

---

## Authenticated — registration (add a passkey)

Sudo-gated: a fresh confirmation (or password re-auth) must have seeded a live
management window. Source: `passkeys/api/registration.py`.

### `passkeys.api.registration.begin_registration`

Issue creation options + cache the challenge.
Rate limit: **20 / 3600 s / user**.

- **Args**: `flow` (`"explicit"` default, or `"conditional_create"`).
- **Success** `200`: `{"message": {"state_id": "<opaque>", "options": <CreationOptionsJSON>}}`.
  Inject the `credProps` extension into `options` before `create()` so the
  discoverable state is reported.
- **Errors**: `401 PasskeyConfirmationRequired` when no sudo window is live — the
  body carries `action` (`"passkeys.manage"`), `payload_fingerprint`, and `methods`
  (⊆ `["passkey","password"]`). Run the
  [confirmation](#authenticated--action-confirmation-passkey-signing)
  to mint a grant, then retry `begin_registration`. Also `ValidationError`
  (`passkey_max_per_user` reached; passkeys not configured).

### `passkeys.api.registration.verify_registration`

Verify the creation response and persist the `WebAuthn Credential`. The global
`credential_id_sha256` unique index is the final arbiter of duplicate/hijack.
Rate limit: **20 / 3600 s / user**.

- **Args**: `state_id`, `credential` (the `create()` result JSON), `label`
  (optional; the DocType sanitises + length-caps it).
- **Success** `200`:
  ```json
  { "message": {
      "name": "<credential docname>",
      "label": "Apple Passwords",
      "signal": { "user_handle": "<b64url>", "credential_ids": ["<b64url>", "..."],
                  "name": "user@example.com", "display_name": "User Name" }
  } }
  ```
  The `signal` block feeds the optional WebAuthn Signal API
  (`signalAllAcceptedCredentials` / `signalCurrentUserDetails`).
- **Errors**: `401 CeremonyExpired`; `AuthenticationError` (already registered /
  could-not-verify).

---

## Authenticated — manage credentials

Source: `passkeys/api/credentials.py`. All resolve identity from the session user —
a `name` you don't own returns a **uniform** `DoesNotExistError` (no cross-user
oracle).

### `passkeys.api.credentials.list_credentials`

The caller's own passkeys. A read — **not** sudo-gated.
Rate limit: **60 / 60 s / user**.

- **Args**: none.
- **Success** `200`:
  ```json
  { "message": {
      "credentials": [
        { "name": "…", "label": "…", "enabled": 1, "flagged": 0, "flagged_reason": null,
          "backup_state": 1, "backup_eligible": 1, "discoverable": "Yes",
          "aaguid": "…", "provider": "Apple Passwords", "last_used_at": "…", "creation": "…" }
      ],
      "passkey_only_login": 0
  } }
  ```

### `passkeys.api.credentials.rename_credential`

Display-only; no sudo. Rate limit: **20 / 3600 s / user**.

- **Args**: `name`, `label` (non-empty).
- **Success** `200`: `{"message": {"name": "…", "label": "…"}}`.
- **Errors**: `ValidationError` (empty label).

### `passkeys.api.credentials.delete_credential`

**Sudo-gated** + last-credential guard. Rate limit: **10 / 3600 s / user**.

- **Args**: `name`.
- **Success** `200`: `{"message": {"deleted": "<name>"}}`.
- **Errors**: `401 PasskeyConfirmationRequired` (run the confirmation, retry with the
  grant header); `ValidationError` when it would remove the last passkey of a
  passkey-only account (message surfaced verbatim in `_server_messages`).

### `passkeys.api.credentials.set_passkey_only_login`

Turn password login off/on for the account. Gated on a **passkey grant only** — never
a password/sudo window ("a password must never disable the password-is-not-sufficient
flag"). Enabling additionally needs ≥2 enabled passkeys.

- **Args**: `enabled` (boolean).
- **Success** `200`: `{"message": {"passkey_only_login": 1}}`.
- **Errors**: `401 PasskeyConfirmationRequired` with `methods: ["passkey"]` and a
  `payload_fingerprint` over `{"enabled": <bool>}` — echo it **verbatim** into
  `begin_confirmation` (below); `ValidationError` (<2 passkeys).

---

## Authenticated — action confirmation ("passkey signing")

The re-auth engine that mints the single-use grants the sudo-gated endpoints above
consume, and that any app's `@passkey_protected` method uses. Source:
`passkeys/confirm.py`. Rate limits: **30 / 300 s / user** (`reauth_password`: 5 / 300).

### `passkeys.confirm.begin_confirmation`

Mint UV-required assertion options bound to an action (+ optional payload).

- **Args**: `action` (stable, globally unique action ID), and **either** `params` (the raw call
  args — the server computes the fingerprint) **or** `payload_hash` (a server-issued
  `payload_fingerprint` echoed verbatim — never compute it client-side). The two are
  mutually exclusive.
- **Success** `200`: `{"message": {"state_id": "…", "options": <RequestOptionsJSON>,
  "payload_fingerprint": "…", "methods": ["passkey","password"],
  "action_label": "Release payment", "parameter_summary": [{"label":"Payment","value":"PAY-1"}]}}`.
  The display fields are optional decorator metadata. `display_params` must be a subset of
  `bind_params`; undeclared values are never exposed and display metadata does not alter grant
	  binding.
	  A protected call publishes this policy to site-scoped Redis before returning its 401, so a
	  subsequent begin/reauth request may land on another worker. Unknown action IDs fail closed and
	  do not offer password fallback.

### `passkeys.confirm.verify_confirmation`

Verify the UV assertion, mint the grant.

- **Args**: `state_id`, `credential` (assertion JSON).
- **Success** `200`: `{"message": {"grant": "<opaque token>"}}`. Attach it as
  `X-Passkey-Grant: <token>` on the retried protected call.

### `passkeys.confirm.reauth_password`

Password fallback: seed a sudo window (bare `pwd`) or mint an action grant
(`pwd` + `action` + `payload_fingerprint`, only if the action allows password
fallback). Rate limit: **5 / 300 s / user**.

- **Args**: `pwd`, `action` (optional), `payload_fingerprint` (optional).
- **Success** `200`: `{"message": {"grant": "…"}}` (with `action`) or a seeded window.

---

## Authenticated — supporting endpoints

- **`passkeys.passkey.get_signal_data`** — returns `{rp_id, user_handle,
  credential_ids}` for the caller so a client can drive the WebAuthn Signal API.
  Rate limit: 60 / 60 s / user. Source: `passkeys/passkey.py:get_signal_data`.
- **`passkeys.passkey.record_nudge`** — folds an enrollment-nudge event
  (`"shown"` / `"declined"` / `"opt_out"`) into per-user cadence state; best-effort
  telemetry, safe to omit. Rate limit: 30 / 3600 s / user.
- **`passkeys.passkey.record_enforcement`** — records `"defer"` or `"incapable"`. A defer consumes
  at most one grace login per user/session, atomically across tabs/workers. Rate limit: 30 / 3600 s
  / user.
- **`passkeys.passkey.get_app_translations`** (`GET`) — the app's i18n catalog, for
  rendering the shipped copy on v15/v16 pages. Rate limit: 30 / 60 s / IP.

---

## See also

- [`custom-ui.md`](custom-ui.md) — the headless JS API (does the encoding/CSRF/retries).
- [`mobile-apps.md`](mobile-apps.md) — native iOS/Android association (well-known files).
- [`configuration.md`](configuration.md) — RP ID / origins the ceremony must run on.
- [`security.md`](security.md) — the enforced model, what is trusted, disclosure.
