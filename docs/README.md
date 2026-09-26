# Passkeys for Frappe: documentation

Passkey (WebAuthn / FIDO2) sign-in and action confirmation for Frappe and ERPNext v15 and v16.
New here? Start with [Install](install.md), then [Configuration](configuration.md).

## Set up and run

- [**Install**](install.md): install, upgrade, uninstall, the version matrix, and reverse-proxy
  / RP ID / origin requirements.
- [**Configuration**](configuration.md): every Passkey Settings field, its default, and the
  security consequence of changing it.
- [**Operations**](operations.md): pre-production checks, RP ID and domain changes, backup and
  restore, incident response, revocation, and monitoring.
- [**Recovery**](recovery.md): System Manager recovery through Desk, then Administrator and
  account-specific console procedures when no manager can sign in.

## Build on it

- [**Custom UI**](custom-ui.md): build your own passkey login and management screens with the
  `frappe.passkeys.headless` JavaScript API, protect your own methods with `@passkey_protected`,
  or restyle the shipped cards.
- [**REST API**](rest-api.md): the whitelisted endpoints (arguments, response shapes, CSRF, rate
  limits) for a native app or a no-JS single-page app.
- [**Mobile apps**](mobile-apps.md): let a native iOS or Android app share the site's passkeys:
  trusted app origins, the two well-known association files, and the endpoints.

## Security

- [**Security model**](security.md): what the app enforces, what it trusts, residual risks, and
  disclosure.
- [**WebAuthn Level 3 support**](webauthn-l3.md): which WebAuthn L3 relying-party steps and
  browser features the app supports, where each is handled, and what is not supported yet.
- [**Why passkeys are safer**](https://andrometiq.com/software/passkey/): a short illustrated
  explainer for decision makers.
- [**Security policy**](../SECURITY.md): how to report a vulnerability privately.

## Project

- [**Changelog**](../CHANGELOG.md): what changed in each release.
- [**Upstream proposal**](upstream/): a design and validation checklist for adopting passkeys in
  Frappe core.
- [**Contributing**](../CONTRIBUTING.md): development setup, branches, tests, and releases.
