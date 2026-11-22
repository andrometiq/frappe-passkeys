# Releases

## Which line to install

- **Frappe v15** (v15.108.0 and newer): branch `version-15`, releases 15.x.y.
- **Frappe v16** (v16.18.3 and newer): branch `version-16`, releases 16.x.y.
- **Frappe develop**: branch `develop`. Unreleased; not for production.

Every change lands on `develop` first. A release moves both version branches to it and tags
each one ([CONTRIBUTING.md](CONTRIBUTING.md#branches)).

## What a version number means

Take `16.0.8`:

- **16** is the Frappe major version it runs on.
- **8** goes up with every release. 15.0.8 and 16.0.8 have the same features and fixes.
- **0** has not changed yet. It goes up when a release removes or renames public API.

Before you upgrade, read the release's **Upgrade notes** in the [changelog](CHANGELOG.md).

## Public API

These are public; anything else can change in any release.

- `@passkey_protected` and its arguments, in `passkeys/confirm.py`
  ([Custom UI](docs/custom-ui.md#action-confirmation-for-your-own-methods)).
- The endpoints in the [REST API](docs/rest-api.md) reference: paths, arguments, responses and
  `exc_type` error names. Match on `exc_type`, never on message text.
- The JavaScript globals in [Custom UI](docs/custom-ui.md#the-public-javascript-surface), such as
  `frappe.passkeys.headless`, and the CSS class hooks in its
  [markup contract](docs/custom-ui.md#semantic-markup-contract).
- Passkey Settings field names ([Configuration](docs/configuration.md)) and the Activity Log event
  names ([Operations](docs/operations.md#monitoring-the-risk-events)).
- The well-known files and endpoints for [mobile apps](docs/mobile-apps.md).

## How something is retired

1. A release adds the new name and keeps the old one working. The changelog says what to switch to.
2. The old name goes in a later release that raises the middle number, and that release's Upgrade
   notes say so.

A security fix may break this when keeping the old behaviour is the vulnerability; the changelog
says so under **Security**.

Why: 15.0.4 renamed a Passkey Settings field
(`passkey_allow_first_enrollment_on_weak_login` → `passkey_allow_first_enrollment_on_external_login`)
in a patch release, with no overlap. Code that read the old name had to change in the same upgrade.
