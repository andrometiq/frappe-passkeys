# Testing

The app ships three test layers, all runnable locally:

| Layer | Runner | What it covers |
| --- | --- | --- |
| JS pure cores | `node --test passkeys/tests/js/*.test.js` | The hand-written login/confirm/manage bundles' pure logic (no bench, no jsdom) via each bundle's Node seam. |
| Python | `bench --site <site> run-tests --app passkeys` | The ceremony engine, endpoints, settings validators, sudo/grant state, enforcement, and the **browserless WebAuthn test mode** below. |
| Cypress (UI) | `bench --site <site> run-ui-tests passkeys` | Full browser flows, driven by the Chromium CDP virtual authenticator. |

CI runs all three across a `version-15` / `version-16` / `develop` matrix; see `.github/workflows/ci.yml`.

## Browserless WebAuthn test mode

WebAuthn is normally impossible to test without a browser (or a CDP virtual
authenticator). This app ships a **bench-guarded fake-service layer**,
`passkeys/tests/fake_webauthn.py`, that runs the *real* ceremonies — real
server-minted challenges, the unmodified `py_webauthn` verifier, and every
app-side check — driven by a deterministic software authenticator
(`SoftAuthenticator`) instead of a browser. It lets you exercise the full
`register → login → delete` pipeline in a plain `bench run-tests`, and it is
reusable: **adopt it in your own app's CI** to test passkey flows headlessly.

### Using it

```python
from passkeys.tests import fake_webauthn

# One call: register a passkey, log in with it (discoverable, no identifier),
# then delete it — all through the real verify paths, on a throwaway user.
report = fake_webauthn.round_trip()
assert report["session_matches"] and report["credential_gone"]

# Or enrol a real passkey for a specific user (committed), e.g. to seed a fixture
# a browser session or a follow-up API call will then see:
fake_webauthn.enable()                      # point settings at a test RP + origin
fake_webauthn.enroll(user="alice@example.com")
```

`enable(rp_id, origin)` writes the RP ID + origin and turns login on;
`enroll(user=None, seed, alg, …)` runs a real registration ceremony for a user;
`round_trip(…)` chains register → login → delete and returns a structured report.
`alg` accepts `-7` (ES256, default) or `-8` (Ed25519).

### The guard — never callable in production

Every whitelisted entry point calls `_guard()` first, byte-for-byte the
`ui_test_helpers._guard` contract:

```python
frappe.only_for("System Manager")
if not (frappe.conf.get("developer_mode") or frappe.flags.in_test):
    frappe.throw(...)   # hard refuse
```

So the fake service is reachable **only** by a System Manager on a bench that is
in developer mode or running tests — never on a production site, and never by a
guest. It sits on no `hooks.py` chain, ships no `allow_guest` endpoint, and folds
away with the `shims/` on a future core merge.

### What it does NOT do

- **It adds no skip-verification path.** Nothing in the module touches
  `engine.py`. The software authenticator emits spec-valid payloads that pass the
  *unmodified* verifier; a tampered assertion is still rejected (proven by
  `test_fake_webauthn.test_tampered_assertion_is_rejected_by_the_real_verifier`).
  There is no "accept anything in test mode" door — because that door, if it
  existed, would be a permanent backdoor.
- **It relaxes only the enable-time HTTPS validator.** `enable()` writes settings
  directly (`set_single_value`), so an `http://*.localhost` origin is accepted for
  a local bench — but the **ceremony-time** `expected_origin` check the verifier
  enforces is fully intact (proven by
  `test_enable_relaxes_only_the_enable_time_https_validator`).
- **Its keys never reach a production store.** The authenticator is
  seed-derived (labelled test keys) and only ever invoked behind the guard.
