<div align="center" markdown="1">
	<img src=".github/logo.png" width="80" height="80" alt="Passkeys for Frappe" />
	<h1>Passkeys for Frappe</h1>

**Passwordless, phishing-resistant WebAuthn authentication for Frappe**
</div>

<div align="center">
	<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-success.svg" alt="License: MIT" /></a>
	<a href="https://github.com/Andrometiq/frappe-passkeys/actions/workflows/ci.yml"><img src="https://github.com/Andrometiq/frappe-passkeys/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
	<img src="https://img.shields.io/badge/Frappe-v15%20%C2%B7%20v16%20%C2%B7%20develop-0089FF.svg" alt="Frappe v15 · v16 · develop" />
	<img src="https://img.shields.io/badge/WebAuthn-Level%203-4F46E5.svg" alt="WebAuthn Level 3" />
</div>

<div align="center">
	<img src=".github/screenshots/login.png" alt="Sign in with a passkey" width="371" />
</div>

> **Passkeys end phishing, credential stuffing, and password-database breaches at the root: there is no shared secret to steal, reuse, or replay, and a user's private key never leaves their device.** If that sounds like something every Frappe site should have — and every Frappe maintainer should ship by default — read the short, plain-language, diagram-driven explainer of exactly **why**: **[Why passkeys are safer — and when they aren't](https://andrometiq.github.io/frappe-passkeys/why-passkeys.html)** ([source](docs/why-passkeys.html)).

## Passkeys for Frappe

Passkeys bring [WebAuthn / FIDO2](https://fidoalliance.org/passkeys/) authentication to any Frappe
site — the same fingerprint, face, screen-lock, or security-key sign-in people already use with their
Apple, Google, and Microsoft accounts. It is built to be **mergeable into Frappe core**: no
monkeypatching, one codebase across v15 / v16 / develop, and a layout that mirrors its intended home
in `frappe/frappe`.

The app adds three independent capabilities. The two login modes are switchable and ship **off**;
action confirmation is a developer primitive that stays available for any app to build on.

### Key Features

- **Passwordless login** — a discoverable-credential ("passkey") sign-in on the login page, with
  conditional UI (autofill), an explicit button, and cross-device (hybrid / QR) support.

- **Passkey as a second factor** — after a password, a passkey step-up that speaks Frappe's own
  two-factor envelope, with a mid-flow one-time-code fallback.

- **Action confirmation** — `@passkey_protected` puts a fresh, single-use passkey confirmation on any
  sensitive whitelisted method, bound to the exact action and payload before it runs.

- **Native-handover aware** — integration uses sanctioned hooks and whitelisted endpoints. Fresh
  installation is blocked when `frappe.passkey` exists. An already-installed app becomes dormant
  only when core explicitly advertises
  `FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`; module presence alone is not
  treated as a safe handover.

- **Secure by default** — every mode ships off; user verification and sign-count clone-detection are
  enforced, per-user and per-IP rate limits guard every ceremony, and a passkey-only account can never
  lock its last door.

<details>
<summary>Screenshots</summary>

**Self-service management** — users add, rename, and remove their own passkeys at `/passkeys`, and can
switch their account to passwordless-only.

![Manage your passkeys](.github/screenshots/portal.png)

**Administrator settings** — every mode stays off until an administrator turns it on, with a
one-way-door warning on the Relying Party ID.

![Passkey Settings](.github/screenshots/settings.png)

</details>

## Installation

> **Project status: pre-release.** This repository has no tagged stable release. The current branches
> are release candidates under active hardening, not a blanket production-readiness claim. Validate
> the exact candidate on staging and complete the [release checklist](docs/release-checklist.md)
> before deploying it to an authentication-critical site.

```bash
# Pick the branch that matches your Frappe version: version-15, version-16, or develop
bench get-app --branch version-16 https://github.com/Andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
```

Installing is **not** enabling — every login mode ships off. Before enabling one, set a compatible
site `host_name` and/or explicit Passkey Origins, review the resolved Relying Party ID and exact
origin set, and verify that the set is non-empty. The RP ID is credential scope, not proof that
`https://<rp_id>` serves this site; changing the RP ID later invalidates every enrolled passkey.

### Supported versions

| Frappe | Supported | Notes |
| --- | --- | --- |
| **v15** | v15.107.0 and newer | The `webauthn` library needs `cryptography>=46` **and** `pyOpenSSL>=26`, which v15 ships together only from v15.107.0. A `before_install` guard aborts on anything older with a clear message. |
| **v16** | Candidate branch | Use `version-16`; release CI tests a pinned Frappe baseline. Re-run the candidate against the exact Frappe patch level you deploy. |
| **develop** | Integration target | Pre-release Frappe integration only. Daily moving-tip runs fail visibly on drift but are compatibility signals, not release attestations. |

Python `>=3.10,<3.15` is required. See [`docs/install.md`](docs/install.md) for the full matrix and
reverse-proxy / RP-ID / origin requirements.

## Documentation

- [**Install**](docs/install.md) — install, upgrade, uninstall, the version matrix, and reverse-proxy
  / RP-ID / origin requirements.
- [**Configuration**](docs/configuration.md) — every Passkey Settings field, its default, and the
  security consequence of changing it.
- [**Custom UI**](docs/custom-ui.md) — build your own passkey login and management screens with the
  markup-free `frappe.passkeys.headless` JavaScript API, or restyle the shipped barebones cards.
- [**REST API**](docs/rest-api.md) — the raw whitelisted endpoints (args, response shapes, CSRF,
  rate limits) for a native app or a no-JS single-page app.
- [**Mobile apps**](docs/mobile-apps.md) — let a native iOS/Android app (Flutter-first) share the
  site's passkeys: Trusted App Origins, the two well-known association files, and the endpoints.
- [**Operations**](docs/operations.md) — day-two playbooks: RP-ID / domain changes, backup / restore,
  incident response, revocation, and monitoring.
- [**Recovery**](docs/recovery.md) — locked-out user and locked-out admin recovery, with exact
  `bench console` commands.
- [**Security**](docs/security.md) — the security model in operator terms: what the app enforces, what
  it trusts, residual risks, and disclosure.
- [**Release checklist**](docs/release-checklist.md) — required candidate, staging, recovery, and
  deployment checks.
- [**Security policy**](SECURITY.md) — supported security-reporting scope and private disclosure.
- [**Changelog**](CHANGELOG.md) — release-facing changes; all current work remains unreleased.
- [**Upstream proposal**](docs/upstream/) — a design and validation checklist for possible core
  adoption. It does not claim that current Frappe core is compatible.

## Development

Install the app and `pre-commit install`, then run the suites before you push — the exact commands
(server, JS unit, and Cypress) live in [`CONTRIBUTING.md`](CONTRIBUTING.md#development-setup).

The app carries server, dependency-free JavaScript, and Cypress end-to-end suites. Release CI runs
them against reviewed, pinned Frappe v15, v16, and develop baselines. A separate moving-tip workflow
fails visibly on compatibility drift but is not a release attestation; neither workflow replaces
staging validation for the exact deployment candidate.

## Upstream intent

This app is intended to inform a future native Frappe implementation.
[`docs/upstream/`](docs/upstream/) is a proposal that must be rebased, reviewed, and validated
against the core revision used for any PR. Current core compatibility is not assumed. Fresh installs
are blocked by `frappe.passkey` module presence, but automatic dormancy requires core's exact,
explicit handover capability marker; without it, an installed app remains active rather than
silently yielding to a partial implementation.

## Contributing

Bug reports, fixes, and features are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branch
model, commit-message conventions, and how to run the test suites.

## License

[MIT](LICENSE)

<br>
<div align="center">
	Made for the <a href="https://frappe.io">Frappe</a> community.
</div>
