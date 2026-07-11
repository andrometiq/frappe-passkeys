# WebAuthn deterministic test fixtures

Golden request/response vectors for testing a server-side WebAuthn (passkey)
verifier **without a browser or an authenticator**. Every vector is a complete
WebAuthn **Level 3 JSON wire format** payload — exactly what
`PublicKeyCredential.toJSON()` produces in the browser and what the frappe
endpoint will receive in the request body — plus the server-side context
(RP ID, origin, challenge, stored public key, stored sign count) needed to
verify it, and the declared outcome.

Everything is deterministic: fixed seed-derived keys, fixed challenges,
RFC 6979 deterministic ECDSA. Regenerating produces byte-identical files
(proven by `test_vectors_are_deterministic`).

**The private keys in `generator.py` are intentionally public TEST keys.
Never use them outside tests.**

## Files

| File | Purpose |
| --- | --- |
| `generator.py` | Software authenticator + vector builder. `python generator.py --out vectors/` regenerates everything. Needs `cryptography` + `cbor2`. |
| `vectors/*.json` | 35 golden vectors (15 positive, 20 negative), one file each. 4 negatives are **library-divergent** (crossOrigin/topOrigin — py_webauthn accepts them; see below). |
| `test_vectors_selfcheck.py` | Proof of correctness: every vector behaves as declared under [py_webauthn](https://pypi.org/project/webauthn/) `>=2.8,<3` (an independent, widely-used implementation). Needs `webauthn` + `pytest`. |

## Vector schema

```jsonc
{
  "name": "auth-signcount-regression",
  "kind": "authentication",            // or "registration"
  "description": "...",
  "expect": "fail",                    // or "pass"
  "context": {                         // server-side verification inputs
    "expected_rp_id": "example.com",
    "expected_origin": "https://example.com",
    "expected_challenge": "<base64url>",       // challenge the server issued
    "require_user_verification": true,
    "require_user_presence": true,             // registration only
    "credential_public_key": "<base64url COSE>",   // authentication only
    "credential_current_sign_count": 42            // authentication only
  },
  "credential": { /* WebAuthn L3 JSON — feed to the endpoint verbatim */ },
  // expect=pass → what the verifier must extract:
  "expected": {
    "credential_id": "<base64url>",
    "credential_public_key": "<base64url COSE>",   // registration only
    "alg": -7,                                     // registration only
    "sign_count": 0,                               // reg: initial counter to store
    "new_sign_count": 1,                           // auth: counter to store
    "user_handle": "<base64url>",                  // auth only
    "user_verified": true,
    "credential_device_type": "single_device",     // or "multi_device" (BE=1)
    "credential_backed_up": false                  // BS flag
  },
  // expect=fail → how it must be rejected:
  "expected_error": "InvalidAuthenticationResponse",     // py_webauthn class name
  "expected_error_substring": "sign count",              // py_webauthn message hint
  // ONLY on library-divergent vectors (crossOrigin/topOrigin):
  "library_expect": "pass",            // py_webauthn 2.8's outcome (≠ expect)
  "library_expected": { /* verified values py_webauthn returns */ }
}
```

`expected_error` / `expected_error_substring` name the **py_webauthn**
exception; the frappe test suite should map them to its own failure taxonomy
(any rejection of the ceremony is acceptable — what matters is that the
vector is refused, and for which security reason).

**Library-divergent vectors** carry `library_expect`/`library_expected`: the
app contract (`expect: "fail"`) and py_webauthn's behavior differ by design.
For these, `expected_error`/`expected_error_substring` are `null` — the
rejection is **app-side only**, py_webauthn raises nothing. The self-check
asserts the *library* outcome (pinning the gap so an upstream change is
noticed); the frappe suite must assert the *app* outcome (`expect`).

## Coverage

Registration (attestation `none`): ES256 / Ed25519 / RS256 happy paths;
UV-off accepted when not required; BE/BS combinations (synced-passkey
detection); nonzero initial sign count; **credProps extension result in
`clientExtensionResults`** (`reg-es256-credprops` — the verifier must read
`credProps.rk` from the credential JSON itself and mark the credential
discoverable; py_webauthn drops `clientExtensionResults` at parse and its
`VerifiedRegistration` has no extension output). Rejections: rpIdHash
mismatch, origin mismatch, challenge mismatch, UV required but absent, UP
absent, clientData type mismatch, BS-without-BE (impossible backup state),
**crossOrigin:true (± topOrigin) — app-side rejection, library-divergent**.

Authentication: same three algorithms; counter increment; counter-less
authenticator (0 → 0 accepted); UV-off accepted when not required; synced
passkey flags. Rejections: **sign-count regression and replay (equal
count)**, rpIdHash mismatch, origin mismatch, challenge mismatch,
**credential substitution** (assertion signed by a different key than the
registered credential — signature must fail), UV required but absent, UP
absent, clientData type mismatch, **crossOrigin:true (± topOrigin) —
app-side rejection, library-divergent**.

## How the frappe test suite consumes these

No browser, no mocking of crypto — unit tests drive the server verifier with
the vector's `credential` dict and pin the server state from `context`:

```python
import json
from pathlib import Path

import pytest

VECTORS = sorted((Path(__file__).parent / "fixtures" / "vectors").glob("*.json"))

@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_webauthn_verifier(path):
    v = json.loads(path.read_text())

    # 1. Seed server state from v["context"]:
    #    - stash context["expected_challenge"] in the pending-challenge store
    #      (cache/session) for the test user, as begin-registration/-login would
    #    - for authentication vectors, create the stored credential row with
    #      context["credential_public_key"] and
    #      context["credential_current_sign_count"]
    #    - configure the site's RP ID / origin to context values
    #      ("example.com" / "https://example.com")

    # 2. POST v["credential"] to the finish-registration / finish-login
    #    endpoint (frappe test client), or call the verify function directly.

    # 3. Assert:
    if v["expect"] == "pass":
        pass  # ceremony accepted; stored values match v["expected"]
              # (credential_id, public key, sign counter, backup flags)
    else:
        pass  # ceremony rejected (v["description"] says why it must fail);
              # no credential row created / no login session issued
```

Points worth pinning in the frappe tests beyond accept/reject:

- after a positive registration, the stored credential matches
  `expected.credential_id`, `expected.credential_public_key` (COSE bytes),
  `expected.sign_count`, and the backup/device-type fields;
- after a positive authentication, the stored counter becomes
  `expected.new_sign_count`;
- a negative vector must not mutate state (no credential created, counter
  unchanged, no session).

Because the fixtures are deterministic, tests can also hard-code derived
values (credential IDs, challenges) without regenerating anything.

## Regenerating / extending

```sh
python -m venv .venv && . .venv/bin/activate
pip install "cryptography>=42" cbor2 "webauthn>=2.8,<3" pytest
python generator.py --out vectors/
pytest test_vectors_selfcheck.py   # must be green before committing vectors
```

Add new cases in `build_vectors()` (one `SoftAuthenticator` call with the
right knobs), regenerate, and keep the self-check green — the py_webauthn
round-trip is what makes a vector trustworthy.

## crossOrigin/topOrigin behavior in py_webauthn 2.8

Empirical probe (py_webauthn 2.8.0, 2026-07-05), every case a real,
correctly-signed ceremony run through `verify_registration_response` /
`verify_authentication_response`:

| clientDataJSON variant | registration | authentication |
| --- | --- | --- |
| `crossOrigin` absent | PASS | PASS |
| `crossOrigin: false` | PASS | PASS |
| `crossOrigin: true` | **PASS** | **PASS** |
| `crossOrigin: true` + `topOrigin` | **PASS** | **PASS** |
| `crossOrigin: false` + `topOrigin` (spec-illegal combo) | PASS | PASS |
| `topOrigin` without `crossOrigin` | PASS | PASS |
| `expected_origin` as list, origin ∈ list | PASS | PASS |
| `expected_origin` as list, origin ∉ list | REJECT `Invalid…Response` "Unexpected client data origin" | same |

Conclusions:

- **py_webauthn 2.8 does NOT enforce crossOrigin.** `parse_client_data_json`
  copies it into `CollectedClientData.cross_origin`, but neither verify path
  ever reads it — `crossOrigin: true` verifies cleanly. Any RP policy of
  "reject cross-origin iframe ceremonies" MUST be an app-side check on the
  parsed clientDataJSON.
- **topOrigin is invisible to the library.** It is not parsed at all
  (`CollectedClientData` has no such field), so it can never be validated
  through py_webauthn. App-side only.
- `expected_origin` accepts a `str` (exact equality) or a `list` (exact
  equality against any element — no wildcards or scheme normalization);
  mismatch raises `InvalidRegistrationResponse` / `InvalidAuthenticationResponse`
  with "Unexpected client data origin".
- `clientExtensionResults` is dropped when the credential JSON is parsed
  (`RegistrationCredential` has no field for it) and `VerifiedRegistration`
  carries no extension output — credProps must be read from the raw
  credential JSON.

The four `*-crossorigin-true*` vectors encode this divergence
(`expect: "fail"` app contract, `library_expect: "pass"` pinned by the
self-check). If a py_webauthn upgrade starts rejecting these, the self-check
goes red — re-probe and revisit the app-side check then.

## py_webauthn (>=2.8,<3) behaviors the vectors encode

Discovered empirically; useful when writing the frappe verifier too:

- **UP is unconditionally required on authentication** (`InvalidAuthentication-
  Response: "User was not present"`); registration has a
  `require_user_presence` parameter (default `True`).
- **Sign-count rule:** rejected iff `(new > 0 or stored > 0) and new <= stored`.
  So `0 → 0` (counter-less authenticators) passes, while equal nonzero counts
  and regressions fail.
- **BS=1 with BE=0 raises `InvalidBackupFlags`**, a sibling of — not a subclass
  of — `InvalidRegistrationResponse`; a naive `except InvalidRegistrationResponse`
  misses it. It is raised from `parse_backup_flags` on both ceremonies.
- clientData type mismatches report enum-ish messages
  (`expected "ClientDataType.WEBAUTHN_CREATE"`), so error-message matching
  should target `"client data type"` rather than the literal `webauthn.create`.
- `verify_authentication_response` takes the stored public key as **COSE bytes**
  (`credential_public_key`), the same bytes `VerifiedRegistration
  .credential_public_key` returns — store those verbatim at registration time.
- py_webauthn accepts unpadded base64url in the JSON wire format (as browsers
  emit); vectors use unpadded encoding throughout.
- soft-webauthn (PyPI 0.1.4) was evaluated and rejected: ES256-only, flags
  hard-coded to `0x41` (no UV/BE/BS control), sign count fixed at 0, no
  negative-case knobs — and its `fido2` dependency pins `cryptography` below
  py_webauthn 2.8's floor.
