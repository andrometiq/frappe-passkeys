# Mobile apps — sharing the site's passkeys (Flutter-first)

A correctly associated native iOS or Android app can use credentials scoped to the site's RP ID.
Cross-surface reuse must be verified on the target OS and app build; it depends on exact origin,
association-file, entitlement/package, and signing-certificate configuration. This guide covers the
server setup, association files, endpoints, and a Flutter integration using the Corbado `passkeys`
package.

## How it works

A passkey is scoped to its **RP ID** — a registrable domain (e.g. `example.com`).
An app that proves it is associated with that domain can create and assert the
*same* domain-scoped credentials:

- **iOS** proves association with an **Associated Domains** entitlement plus a
  `/.well-known/apple-app-site-association` file, and presents
  `origin = https://<RP ID>` in the ceremony. The server accepts it **only when that exact origin is
  present in the resolved Passkey Origins set**; RP ID does not imply origin trust.
- **Android** proves association with a `/.well-known/assetlinks.json` Digital Asset
  Links file, and presents `origin = android:apk-key-hash:<hash>` — **not** an
  `https://` origin. That origin must be added to **Trusted App Origins** so the
  server accepts it.

The RP ID must be a valid WebAuthn RP host within the domain the app associates to, not a public
suffix. It may be an exact application host or a deliberately chosen parent scope. Do not widen it
merely to make mobile association easier.

## 1. Server setup (Passkey Settings)

Open **Passkey Settings** in Desk. The **Mobile Apps** section holds everything below.

### 1.1 RP ID and login mode

- **Passkey RP ID** — the domain your passkeys are scoped to (e.g. `example.com`), or
  blank to derive from the site's `host_name`. The app must associate to this exact
  host.
- **Passkey Origins** — ensure the exact web origins are present. A compatible `host_name` contributes
  its own exact origin, but never synthesizes `https://<RP ID>`. For iOS, add
  `https://<RP ID>` explicitly when that is the origin the native credential API returns.
- **Login with Passkey** — enable it (first-factor passwordless login is the flow an
  app typically drives).

### 1.2 Trusted App Origins (Android only)

Add the Android app's origin, one per line:

```
android:apk-key-hash:<unpadded-base64url-SHA256-of-signing-cert>
```

Example: `android:apk-key-hash:i785YGGJMKRF89cJHnsbBQ-K_a8k6_HrLj0TiAn8eVk`

**Deriving the hash from a SHA-256 fingerprint.** `keytool` prints the fingerprint as
colon-separated hex (`AB:CD:…`); convert it to the origin form:

```js
// hex (colons ignored) -> unpadded base64url
const hex = "AB:CD:...".replace(/[^0-9a-f]/gi, "");
const b64url = Buffer.from(hex, "hex").toString("base64")
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
// origin = "android:apk-key-hash:" + b64url
```

> **Play App Signing gotcha (the single most common failure).** If your app uses
> Play App Signing (default for new apps), Google re-signs the delivered APK. The
> hash that ends up in the ceremony — and that must go here **and** in
> `assetlinks.json` — is **Google's app-signing certificate**
> (Play Console → App integrity → App signing), **not** your local upload key.
> During rollout, include both the upload key and the Play app-signing key.

iOS needs **no** Trusted App Origin entry, but its `https://<RP ID>` origin must be explicitly
trusted under **Passkey Origins** unless the site's compatible `host_name` contributes that exact
origin. Adding a web URL or an iOS-style entry to **Trusted App Origins** is rejected; only
`android:apk-key-hash:<hash>` is accepted there.

### 1.3 Association-file inputs

These four fields generate the two well-known files (section 2):

| Field | Example | Used for |
|---|---|---|
| **Android Package Name** | `com.example.app` | `assetlinks.json` |
| **Android Signing Certificate SHA-256 Fingerprints** (one per line) | Exactly 32 bytes: 64 hex characters, with optional colons | `assetlinks.json` |
| **iOS Team ID** (App ID Prefix) | `ABCDE12345` | `apple-app-site-association` |
| **iOS Bundle ID** | `com.example.app` | `apple-app-site-association` |

Use Google's **Play app-signing** SHA-256 fingerprint (same certificate as the
Trusted App Origin hash — two representations of one cert). A file is served only when
its inputs are complete (both Android fields, or both iOS fields); otherwise that path
returns 404.

## 2. Serve the two association files

Both files must be reachable at the RP-ID domain, over HTTPS, with
`Content-Type: application/json`, HTTP `200`, and **no redirect**:

- `https://<RP ID>/.well-known/assetlinks.json` (Android)
- `https://<RP ID>/.well-known/apple-app-site-association` (iOS, **no** extension)

The app generates both, from the settings above, at these guest endpoints:

- `GET /api/method/passkeys.well_known.assetlinks`
- `GET /api/method/passkeys.well_known.apple_app_site_association`

They return the bare JSON document with the correct content type, and 404 when their
inputs are unconfigured.

### 2.1 Map the well-known paths (reverse proxy)

Frappe **reserves** `/.well-known/*` for its own OAuth / OpenID metadata and returns
404 for anything else — before any app routing runs. So the well-known paths must be
mapped to the endpoints above at the reverse proxy. This is a one-time rule and keeps
the served content in lockstep with your settings.

**nginx** (an internal rewrite — same origin, no external redirect):

```nginx
location = /.well-known/assetlinks.json {
    rewrite ^ /api/method/passkeys.well_known.assetlinks last;
}
location = /.well-known/apple-app-site-association {
    rewrite ^ /api/method/passkeys.well_known.apple_app_site_association last;
}
```

Add these inside the site's `server { … }` block (via your `bench`-managed nginx
template or a custom include so a regenerated config keeps them), above the generic
`location /`.

**Caddy:**

```caddy
handle /.well-known/assetlinks.json {
    rewrite * /api/method/passkeys.well_known.assetlinks
    reverse_proxy <frappe-upstream>
}
handle /.well-known/apple-app-site-association {
    rewrite * /api/method/passkeys.well_known.apple_app_site_association
    reverse_proxy <frappe-upstream>
}
```

The generated responses set `Cache-Control: public, max-age=3600`: association data may be cached
for **one hour**. A proxy/CDN may honor that header; do not configure a longer TTL unless your
certificate-rotation process accounts for it. The endpoint's per-IP limit is only a DoS backstop.

### 2.2 Static alternative (no app involvement)

If you would rather not proxy to the app, curl the generated content and serve it as
static files. The documents look like this (generic examples):

`assetlinks.json`:

```json
[
  {
    "relation": [
      "delegate_permission/common.handle_all_urls",
      "delegate_permission/common.get_login_creds"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.app",
      "sha256_cert_fingerprints": ["AB:CD:EF:01:23:45:67:89:…"]
    }
  }
]
```

`apple-app-site-association`:

```json
{ "webcredentials": { "apps": ["ABCDE12345.com.example.app"] } }
```

Serve each with `Content-Type: application/json` and no redirect. The trade-off:
a static file drifts from your settings — you must re-copy it whenever the Trusted App
Origins / fingerprints change.

### 2.3 Verify

```bash
curl -sI https://<RP ID>/.well-known/assetlinks.json
curl -sI https://<RP ID>/.well-known/apple-app-site-association
```

Both must return `200` with `Content-Type: application/json` and **no** `3xx`.
Google's [Statement List Generator and Tester][gsl] and Apple's associated-domains
tooling validate the files end to end.

## 3. App setup

**Android**

- Put the **package name** and the **Play app-signing** SHA-256 fingerprint in
  `assetlinks.json` (section 1.3).
- Add the Trusted App Origin for that same cert (section 1.2).
- Depend on the `passkeys` Flutter package; Credential Manager needs a recent Android
  + Google Play services (confirm the API floor on the Android prerequisites page).

**iOS**

- Add the **Associated Domains** capability with `webcredentials:<RP ID>`
  (e.g. `webcredentials:example.com`).
- Put `Team ID` + `Bundle ID` in `apple-app-site-association` (section 1.3).
- The `relyingPartyIdentifier` you pass must equal `<RP ID>`.

> Apple fetches the AASA through Apple's CDN, so edits can take time to propagate and
> a fresh install may not see a just-changed file immediately. Use Apple's
> developer/alternate mode during bring-up.

## 4. Endpoints the app calls

Call as `POST /api/method/<path>`; thread `X-Frappe-CSRF-Token` for authenticated
calls. Names and shapes are the app's actual whitelisted methods.

**First-factor passwordless login (guest):**

- `passkeys.passkey.begin_login` — no args. Returns
  `{ enabled, modes: { first_factor, second_factor }, state_id?, options? }`.
  `options` is a **discoverable** request (empty `allowCredentials`, no username) —
  the app must **not** collect a username; the account is resolved from `userHandle`.
- `passkeys.passkey.verify_login` — args `state_id`, `credential` (the assertion JSON;
  `response.userHandle` is **required**). Returns `null` with core's login envelope
  (`message: "Logged In"`, `home_page`) on success. Wire errors: `UVSetupRequired`
  (body carries `setup_id`), `UnknownCredential`, `CeremonyExpired`.
- `passkeys.passkey.complete_uv_setup` — args `setup_id`, `pwd` (only when
  `verify_login` returned `UVSetupRequired`).

**Registration (authenticated; sudo-gated):**

- `passkeys.api.registration.begin_registration` — arg `flow` (`"explicit"` |
  `"conditional_create"`). Returns
  `{ state_id, options: <PublicKeyCredentialCreationOptions JSON> }`.
- `passkeys.api.registration.verify_registration` — args `state_id`, `credential`
  (the creation response JSON), optional `label`. Returns
  `{ name, label, signal: { user_handle, credential_ids: [...] } }`.

**Second factor (password → passkey step-up; guest):**

- `passkeys.passkey.login_with_password` — args `usr`, `pwd`. On a passkey-enrolled
  user sets `verification = { method: "Passkey", options, fallback: { otp } }` +
  `tmp_id` (the `state_id`).
- `passkeys.passkey.verify_second_factor` — args `state_id`, `credential`. `null` on
  success; a re-armable failure returns a fresh `state_id` + `verification.options`
  (retry up to 3), else terminal `CeremonyExpired`.
- `passkeys.passkey.fallback_to_otp` — arg `state_id` (hands off to core OTP).

**Management (authenticated):** `passkeys.api.credentials.list_credentials`,
`rename_credential(name, label)`, `delete_credential(name)` (sudo-gated),
`set_passkey_only_login(enabled)`; `passkeys.passkey.get_signal_data`,
`record_nudge`; `passkeys.passkey.get_app_translations` (guest GET; login-UI i18n).

Every endpoint returns a typed `PasskeyServedByCore` (HTTP 417) only after core explicitly advertises
`FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`. Mere
`frappe.passkey` module presence blocks a fresh app install but does not make an installed app
dormant. Treat 417 as an explicit handover signal, not as generic module detection.

## 5. Flutter walkthrough (Corbado `passkeys`)

The [`passkeys`][pub] package (verified publisher, custom-backend-first) maps 1:1 onto
the JSON these endpoints emit and consume. You do **not** need Corbado's SaaS — you
implement a thin adapter that calls *your* Frappe endpoints. It also ships a
"Passkeys Doctor" (`PasskeyAuthenticator(debugMode: true)`) that diagnoses the
association-file / entitlement misconfigurations that dominate mobile bring-up.

**Register**

```dart
final begin = await frappe.beginRegistration(flow: 'explicit'); // {state_id, options}
final req = RegisterRequestType.fromJson(begin['options']); // reads rp, user,
    // authenticatorSelection, pubKeyCredParams, excludeCredentials
final res = await authenticator.register(req); // {id, rawId, clientDataJSON,
    // attestationObject, transports}
await frappe.verifyRegistration(
  stateId: begin['state_id'],
  credential: {
    'id': res.id, 'rawId': res.rawId,
    'response': {
      'clientDataJSON': res.clientDataJSON,
      'attestationObject': res.attestationObject,
      'transports': res.transports,
    },
  },
);
```

**Authenticate (discoverable / usernameless)**

```dart
final begin = await frappe.beginLogin(); // {state_id, options}
final req = AuthenticateRequestType(
  relyingPartyId: rpId,
  challenge: begin['options']['challenge'],
  mediation: MediationType.Optional, // discoverable — no allowCredentials
  preferImmediatelyAvailableCredentials: false,
  timeout: begin['options']['timeout'],
  userVerification: 'preferred',
  allowCredentials: const [],
);
final res = await authenticator.authenticate(req); // {id, rawId, clientDataJSON,
    // authenticatorData, signature, userHandle}
await frappe.verifyLogin(
  stateId: begin['state_id'],
  credential: {
    'id': res.id, 'rawId': res.rawId,
    'response': {
      'clientDataJSON': res.clientDataJSON,
      'authenticatorData': res.authenticatorData,
      'signature': res.signature,
      'userHandle': res.userHandle, // REQUIRED — account is resolved from it
    },
  },
);
```

**Adapter shape.** Implement a `FrappePasskeyServer` with
`beginRegister()/finishRegister()`, `beginLogin()/finishLogin()`,
`loginWithPassword()/finishSecondFactor()` that wrap section 4 and thread the
`state_id` / `tmp_id` + the CSRF token. Handle the typed wire errors explicitly:
`UVSetupRequired` (collect the password, call `complete_uv_setup`), `CeremonyExpired`
re-arm on the second factor, and `PasskeyServedByCore` (417).

If you must drop the third-party dependency, the escape hatch is ~2 Kotlin
(`androidx.credentials.CredentialManager`) and ~2 Swift
(`ASAuthorizationPlatformPublicKeyCredentialProvider`) methods marshaling the same
WebAuthn JSON — the `passkeys` package is exactly that, maintained and multi-platform,
so default to it.

## 6. Gotchas & test matrix

- **Cross-surface reuse.** Register a passkey on the **web**, then assert it in the
  **app** (and vice-versa) — proving the same credential is shared.
- **Android — wrong fingerprint.** Using the upload key instead of the Play
  app-signing key means the app presents an `apk-key-hash` origin that is not in
  Trusted App Origins; the assertion fails with an authentication error. Fix by using
  Google's app-signing cert everywhere.
- **iOS — AASA propagation.** Allow time for Apple's CDN; use the developer/alternate
  mode during bring-up.
- **Discoverable-only first factor.** `begin_login` returns an empty
  `allowCredentials`; the app must **not** collect a username — the account is
  resolved server-side from `userHandle`, which `verify_login` requires.
- **Native enrolment `credProps`.** A native registration carries no
  `authenticatorAttachment` and no `clientExtensionResults.credProps`, so the engine
  cannot read residentKey and records `discoverable = "Unknown"`. The **explicit**
  registration flow already promotes `Unknown → Yes` (it pins `residentKey=required`),
  so a native-registered credential is stored as discoverable and works for
  usernameless login. A `conditional_create` registration keeps `Unknown`
  (residentKey is genuinely unknown there). No action needed — just expect it.

[pub]: https://pub.dev/packages/passkeys
[gsl]: https://developers.google.com/digital-asset-links/tools/generator
