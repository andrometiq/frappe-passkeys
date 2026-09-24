# WebAuthn Level 3 support

This page maps the app against the relying-party (RP) requirements of
[Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) (W3C Recommendation, 25 August 2026).
It was checked on 2026-09-24 against the app's source and the pinned server library,
[py_webauthn](https://github.com/duo-labs/py_webauthn) `2.8.0`.

"py_webauthn" in the tables means the check runs inside the library's
`verify_registration_response` / `verify_authentication_response`, which the app calls from
[`passkeys/engine.py`](../passkeys/engine.py). Everything else is app code.

## Fully supported

### Registering a new credential (§7.1)

| Spec step | Where | Notes |
|---|---|---|
| Parse `clientDataJSON` (UTF-8, JSON) | py_webauthn | |
| `C.type` is `webauthn.create` | py_webauthn | |
| `C.challenge` matches the issued challenge | py_webauthn | Challenge is single-use server state, consumed before verification ([`state.py`](../passkeys/state.py)). |
| `C.origin` is expected | py_webauthn + app | Exact match against the site's configured origin list ([`policy.py`](../passkeys/policy.py)); the request host must also be in that list ([`ceremony.py`](../passkeys/ceremony.py)). |
| `C.crossOrigin` / `C.topOrigin` | app, [`engine.py`](../passkeys/engine.py) `_reject_cross_origin` | The RP expects no cross-origin iframes, so either member rejects the ceremony. py_webauthn does not check these. |
| `rpIdHash` is SHA-256 of the RP ID | py_webauthn | |
| UP flag set unless `mediation: "conditional"` | py_webauthn, flag set by [`api/registration.py`](../passkeys/api/registration.py) | UP is waived only for the server-recorded conditional-create flow, never on client input. |
| UV flag when the RP requires it | app | Registration does not require UV; the UV bit is recorded as `uvInitialized` and gates later use (see below). |
| BS set only if BE set | py_webauthn | Its own exception branch in `engine.py`, so it fails as a clean 401. |
| Credential `alg` is one of the offered `pubKeyCredParams` | py_webauthn + app | Offered: EdDSA, ES256, RS256. The app re-reads `alg` from the COSE key, not from the client-reported value. |
| Attestation format and statement verification | py_webauthn | The app requests `attestation: "none"`; see [Not supported](#not-supported) for trust anchors. |
| Credential ID ≤ 1023 bytes | app, `engine.py` | |
| Credential ID not already registered for any user | app, `api/registration.py` | Global unique index on the credential ID hash; a duplicate fails closed. |
| Store the credential record | app, `api/registration.py` | Stores id, public key, sign count, `uvInitialized`, transports, BE, BS, attestation object, client data, RP ID, and a user-editable label. |
| Process extension outputs | app, `engine.py` | `credProps.rk` is read from the raw response and stored as discoverable Yes / No / Unknown. Other outputs are ignored. |
| Store under the user in `pkOptions.user` | app, `api/registration.py` | Ceremony state is bound to the user and session that began it. |

### Verifying an authentication assertion (§7.2)

| Spec step | Where | Notes |
|---|---|---|
| Credential is in `allowCredentials` when that list is non-empty | app, [`passkey.py`](../passkeys/passkey.py) (second factor), [`confirm.py`](../passkeys/confirm.py) (action confirmation) | Passwordless login uses an empty list (discoverable credentials). |
| Identify the user: credential belongs to the account; `userHandle` matches when present | app, `passkey.py`, `confirm.py` | Passwordless login requires `userHandle` and resolves the account from it. |
| Parse `clientDataJSON` | py_webauthn | |
| `C.type` is `webauthn.get` | py_webauthn | |
| `C.challenge` matches | py_webauthn | Single-use, consumed before verification. |
| `C.origin` is expected | py_webauthn + app | As for registration. |
| `C.crossOrigin` / `C.topOrigin` | app, `engine.py` | Rejected, as for registration. |
| `rpIdHash` | py_webauthn | |
| UP flag set | py_webauthn | |
| UV flag when required | app | Required for passwordless login and action confirmation (the UV bit must be set). A false `uvInitialized` routes passwordless login to the password step-up, and confirmation to a password- or reauth-seeded sudo window. Not required for passkey as a second factor, where the password is the other factor. |
| BS set only if BE set | py_webauthn | |
| Stored BE vs asserted BE | app, `engine.py` + `policy.py` | A change in either direction rejects the assertion. |
| Signature over `authData ‖ SHA-256(clientDataJSON)` | py_webauthn | |
| Signature counter | app, `engine.py` + [`ceremony.py`](../passkeys/ceremony.py) | An equal non-zero counter (replay) always rejects. A regression flags the credential and notifies the owner; a setting turns it into a hard failure. The stored value only moves up. |
| Update `backupState` | app, `ceremony.py` | Refreshed on every successful assertion. |
| Update `uvInitialized` only with an additional factor | app, `passkey.py`, `confirm.py` | The false→true flip needs password knowledge proven in the session (a step-up password, the second-factor password, or a password- or reauth-seeded sudo window). |
| Defer state updates until the RP's extra checks pass | app, `passkey.py` | Counter and flag updates run after the password-version and account checks, before the session is created. |

### Client features

| Feature | Where | Notes |
|---|---|---|
| Conditional mediation (passkey autofill) | [`passkey_login.bundle.js`](../passkeys/public/js/passkey_login.bundle.js), [`passkey_headless.bundle.js`](../passkeys/public/js/passkey_headless.bundle.js) | With `autocomplete="username webauthn"`. |
| Conditional create (automatic passkey upgrade) | [`passkey_desk.bundle.js`](../passkeys/public/js/passkey_desk.bundle.js), `api/registration.py` | Offered only after a password sign-in. |
| `signalUnknownCredential` | `passkey_login.bundle.js` | Sent when the server reports an unknown credential. |
| `signalAllAcceptedCredentials`, `signalCurrentUserDetails` | [`passkey_manage_common.bundle.js`](../passkeys/public/js/passkey_manage_common.bundle.js) | After adding, removing or listing passkeys. |
| `getClientCapabilities` | [`passkey_common.bundle.js`](../passkeys/public/js/passkey_common.bundle.js) | Layered detection with fallback to `isConditionalMediationAvailable` / `isUserVerifyingPlatformAuthenticatorAvailable`. |
| `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` / `toJSON` | `passkey_common.bundle.js` | Manual fallbacks for browsers without them. |
| `credProps` extension | client bundles + `engine.py` | Requested on every registration. |
| Hybrid (phone QR) sign-in | browser | `authenticatorAttachment` is never restricted, so cross-device sign-in stays available. |

## Not supported

| Feature | Why |
|---|---|
| Related Origin Requests (`/.well-known/webauthn`) | Not implemented. Origins must be the RP ID or its subdomains; one site across several unrelated domains is not supported yet. |
| Attestation trust anchors / FIDO Metadata Service | By design. The app requests `attestation: "none"` and does not evaluate certificate chains. The AAGUID is used only to show a provider name, never for policy. |
| `hints` | Not sent. Browsers fall back to their default authenticator choice. |
| Identifier-first login (username, then a non-empty `allowCredentials`) | Not implemented. Passwordless login uses discoverable credentials only; passkey as a second factor does use `allowCredentials`. |
| Extensions other than `credProps` (`prf`, `largeBlob`, `appid`, …) | Not requested; unsolicited outputs are ignored. |
| Cross-origin iframe ceremonies | Rejected by design (`crossOrigin` / `topOrigin`), so a framing page cannot run a ceremony for the site. |

See [Security](security.md) for the wider security model and its known limitations.
