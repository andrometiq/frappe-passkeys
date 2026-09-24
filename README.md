<div align="center" markdown="1">
	<img src=".github/logo.png" width="80" height="80" alt="Passkeys for Frappe" />
	<h1>Passkeys for Frappe</h1>

**Phishing-resistant, passwordless sign-in for Frappe and ERPNext**
</div>

<div align="center">
	<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-success.svg" alt="License: MIT" /></a>
	<a href="https://github.com/Andrometiq/frappe-passkeys/actions/workflows/ci.yml"><img src="https://github.com/Andrometiq/frappe-passkeys/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
	<img src="https://img.shields.io/badge/Frappe-v15%20%C2%B7%20v16%20%C2%B7%20develop-0089FF.svg" alt="Frappe v15 · v16 · develop" />
	<img src="https://img.shields.io/badge/WebAuthn-Level%203-4F46E5.svg" alt="WebAuthn Level 3" />
</div>

<div align="center">
	<img src=".github/screenshots/login.png" alt="The Frappe login page with a Sign in with a passkey button" width="400" />
</div>

> A passkey leaves nothing to phish, reuse, or leak: your server never receives the private key,
> and the browser signs only for your site's real domain. Read the short, illustrated explainer:
> **[Why passkeys are safer, and when they aren't](https://andrometiq.github.io/frappe-passkeys/why-passkeys.html)**
> ([source](docs/why-passkeys.html)).

## Passkeys for Frappe

This app adds [WebAuthn / FIDO2 passkeys](https://fidoalliance.org/passkeys/) to any Frappe site.
Users sign in with the fingerprint, face, screen lock, or security key they already use for their
Apple, Google, and Microsoft accounts. Administrators decide how hard to push adoption, and any app
can require a passkey before a sensitive action runs.

It uses only sanctioned hooks and whitelisted endpoints, with no monkeypatching. One codebase serves
Frappe v15, v16, and develop.

### Key features

- **Passwordless login.** Passkey autofill in the username field (conditional UI), a
  "Sign in with a passkey" button, and cross-device sign-in by scanning a QR code with a phone.

- **Passkey as a second factor.** A passkey step after the password, built on Frappe's own
  two-factor flow. Users can fall back to a one-time code if the site allows it.

- **Confirmation for sensitive actions.** Decorate any whitelisted method with
  `@passkey_protected` and it runs only after a fresh passkey confirmation. Pass
  `allow_password_fallback=True` to also let a user confirm with their password. Each
  confirmation is single-use, expires in about three minutes, and is bound to the user, the
  session, the action, and the values of the arguments you list in `bind_params`. This suits
  approvals such as releasing a bank payment.
  See [Custom UI](docs/custom-ui.md#action-confirmation-for-your-own-methods).

- **Enrollment nudges and enforcement.** Prompt users without a passkey to create one, with a
  prompt cap and a cooldown. Or require enrollment for everyone or for selected roles, with a
  number of grace logins before the prompt blocks.

- **Self-service management.** Users add, rename, and remove their passkeys at `/passkeys`, and can
  switch their own account to passkey-only sign-in.

- **Admin tools.** A security-posture panel on Passkey Settings lists the remaining ways to sign in
  without a passkey and how to close each one. Per-user enforcement exemption and grace-login reset
  sit on the User form. Documented console commands cover lockout recovery.

- **Native mobile apps.** Serve Android Digital Asset Links and the iOS
  `apple-app-site-association` file so a native app shares the site's passkeys.

- **Custom UIs.** Build your own screens with the markup-free `frappe.passkeys.headless`
  JavaScript API, or call the REST endpoints from a native or single-page app.

- **Secure by default.** Every login mode ships off. Passwordless sign-in and passkey action
  confirmations require user verification (a PIN or biometric); a passkey used as the second factor after a
  password does not. A repeated non-zero signature counter is always rejected, and a counter
  regression flags the passkey and emails its owner (or is rejected, if you choose). Relying Party ID and origins come from pinned
  configuration, never from request headers. Guest endpoints are rate-limited per IP and signed-in
  endpoints per user. Switching an account to passkey-only sign-in needs two enabled passkeys, and
  the account's last passkey cannot then be removed.

<details>
<summary>Screenshots</summary>

**Self-service management.** Users add, rename, and remove their own passkeys at `/passkeys`, and
can switch their account to passwordless-only.

<img src=".github/screenshots/portal.png" alt="The My Passkeys page listing two passkeys, MacBook Pro and Pixel 9" width="728" />

**Administrator settings.** Login modes, Relying Party, mobile apps, enrollment, security, and
notifications each have their own tab. Every mode stays off until an administrator turns it on.

<img src=".github/screenshots/settings.png" alt="Passkey Settings, Login Modes tab, with the security posture summary" width="1266" />

</details>

## Installation

```bash
# Pick the branch that matches your Frappe version: version-15 or version-16
bench get-app --branch version-16 https://github.com/Andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
```

Installing is not enabling: every login mode ships off. Before you enable one, set the site's
`host_name` (or an explicit Passkey RP ID) and check the resolved Relying Party ID and origins shown
in Passkey Settings. Changing the RP ID later invalidates every enrolled passkey. Details:
[`docs/install.md`](docs/install.md) and [`docs/configuration.md`](docs/configuration.md).

### Status and supported versions

This is the first public release: **15.0.0** on the `version-15` branch and **16.0.0** on
`version-16`. CI runs the server, JavaScript, and browser end-to-end suites against Frappe v15, v16,
and develop. As with any authentication change, try it on staging before you enable it on a site
that depends on it; [Operations](docs/operations.md#before-you-enable-passkeys-on-a-production-site)
lists what to check.

| Frappe | Branch | Supported |
| --- | --- | --- |
| **v15** | `version-15` | v15.108.0 and newer |
| **v16** | `version-16` | v16.18.3 and newer |
| **develop** | `develop` | Integration target for unreleased Frappe; not for production |

Python `>=3.10,<3.15` is required. See [`docs/install.md`](docs/install.md) for the full matrix and
the reverse-proxy, RP ID, and origin requirements.

## Documentation

- [**Install**](docs/install.md): install, upgrade, uninstall, the version matrix, and reverse-proxy
  / RP ID / origin requirements.
- [**Configuration**](docs/configuration.md): every Passkey Settings field, its default, and the
  security consequence of changing it.
- [**Custom UI**](docs/custom-ui.md): build your own passkey login and management screens with the
  `frappe.passkeys.headless` JavaScript API, or restyle the shipped cards.
- [**REST API**](docs/rest-api.md): the whitelisted endpoints (arguments, response shapes, CSRF,
  rate limits) for a native app or a no-JS single-page app.
- [**Mobile apps**](docs/mobile-apps.md): let a native iOS or Android app share the site's
  passkeys: trusted app origins, the two well-known association files, and the endpoints.
- [**Operations**](docs/operations.md): pre-production checks, RP ID and domain changes, backup and
  restore, incident response, revocation, and monitoring.
- [**Recovery**](docs/recovery.md): locked-out user and locked-out admin recovery, with exact
  `bench console` commands.
- [**Security**](docs/security.md): the security model in operator terms: what the app enforces,
  what it trusts, residual risks, and disclosure.
- [**Security policy**](SECURITY.md): how to report a vulnerability privately.
- [**Changelog**](CHANGELOG.md): what changed in each release.
- [**Upstream proposal**](docs/upstream/): a design and validation checklist for adopting passkeys
  in Frappe core.

## Development

Install the app, run `pre-commit install`, and run the suites before you push. The exact commands
for the server, JavaScript unit, and Cypress suites are in
[`CONTRIBUTING.md`](CONTRIBUTING.md#development-setup).

Release CI runs every suite against pinned Frappe v15, v16, and develop baselines. A separate daily
workflow tests the moving upstream branches and reports drift; it does not replace staging
validation of the exact version you deploy.

## Upstream intent

The app is designed so Frappe core can adopt it: its layout mirrors the intended home in
`frappe/frappe`, and [`docs/upstream/`](docs/upstream/) maps each piece to its core equivalent.
That proposal must be reviewed and validated against the core revision of any future change; no
current core compatibility is assumed.

The app is built to hand over cleanly if core ships passkeys natively. A fresh install is refused
when the Frappe tree contains a `frappe.passkey` module. An installed app goes dormant only when
core explicitly advertises
`FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`; module presence alone is not
treated as a safe handover, so the app stays active rather than yield to a partial implementation.

## Contributing

Bug reports, fixes, and features are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branch
model, commit-message conventions, and how to run the test suites.

## License

[MIT](LICENSE)

<br>
<div align="center">
	Made for the <a href="https://frappe.io">Frappe</a> community.<br>
	Engineered at <a href="https://andrometiq.com">Andrometiq</a>.
</div>
