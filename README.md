# passkeys

Passkey (WebAuthn) authentication for [Frappe](https://github.com/frappe/frappe),
built to be mergeable into Frappe core.

The app adds three capabilities, each independently switchable and shipped **off**:

1. **Passwordless first-factor login** — a discoverable-credential ("passkey")
   sign-in on the login page, with conditional UI (autofill), an explicit
   button, and cross-device (hybrid/QR) support.
2. **Passkey as a second factor** — after a password, a passkey step-up that
   speaks Frappe's own two-factor envelope, with a mid-flow one-time-code
   fallback.
3. **Action confirmation ("passkey signing")** — a re-authentication primitive
   any app can put on a sensitive whitelisted method: `@passkey_protected`
   requires a fresh, single-use passkey confirmation bound to the exact action
   and payload before the method runs.

## Supported versions

Requires **Frappe v15.107.0+, v16, or develop**. The floor is dependency-forced:
the `webauthn` library needs `cryptography>=46` **and** `pyOpenSSL>=26`, which
v15 ships together only from v15.107.0. A `before_install` guard aborts the
install on anything older with a clear message. See [`docs/install.md`](docs/install.md).

## Quickstart

```bash
# Pick the branch that matches your Frappe version: version-15, version-16, or develop
bench get-app --branch version-16 https://github.com/andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
```

Installing is **not** enabling — every login mode ships off. Open **Passkey
Settings**, review the resolved Relying Party ID (changing it later invalidates
every enrolled passkey), then enable the modes you want. Full walkthrough in
[`docs/install.md`](docs/install.md) and [`docs/configuration.md`](docs/configuration.md).

## Documentation

- [`docs/install.md`](docs/install.md) — install, upgrade, uninstall, version
  matrix, reverse-proxy / RP-ID / origin requirements.
- [`docs/configuration.md`](docs/configuration.md) — every Passkey Settings
  field, its default, and the security consequence of changing it; the settings
  interaction matrix in operator terms.
- [`docs/operations.md`](docs/operations.md) — day-two playbooks: RP-ID / domain
  changes, backup / restore, incident response, revocation, monitoring, and the
  self-hoster password-disable override.
- [`docs/recovery.md`](docs/recovery.md) — locked-out user and locked-out admin
  recovery, with exact `bench console` commands.
- [`docs/security.md`](docs/security.md) — the security model in operator terms:
  what the app enforces, what it trusts, residual risks, disclosure.
- [`docs/upstream/`](docs/upstream/) — the plan and patches to move this into
  `frappe/frappe`.

## Development

```bash
cd apps/passkeys
pre-commit install
bench --site <site> run-tests --app passkeys
```

## Contributing

Contributions are welcome. Keep changes mergeable into Frappe core: no
monkeypatching (sanctioned hooks and whitelisted endpoints only), one codebase
across v15 / v16 / develop with feature detection rather than version strings,
and committed files free of any personal or site-specific data. Run
`pre-commit` and the app test suite before opening a pull request.

## Upstream intent

This app is a delivery vehicle for a native Frappe implementation. The layout
mirrors the intended core destination file-for-file, and
[`docs/upstream/`](docs/upstream/) carries the two-stage merge plan and the
concrete patches. On a Frappe that serves passkeys natively, the app detects
this, refuses fresh installs, and every endpoint returns a typed
"served by core" response so it can be uninstalled cleanly.

## License

MIT. See [`LICENSE`](LICENSE).
