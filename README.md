# passkeys

Passkey (WebAuthn) authentication for [Frappe](https://github.com/frappe/frappe):
passwordless first-factor login, passkey as a second factor, and an in-session
action-confirmation ("passkey signing") primitive — built to be mergeable into
Frappe core.

Requires **Frappe v15.107.0+, v16, or develop** (the `webauthn` library needs
`cryptography>=46` and `pyOpenSSL>=26`, which older releases do not ship).

## Installation

```bash
bench get-app https://github.com/frappe/passkeys  # or your fork
bench --site <site> install-app passkeys
```

Installing is not enabling: all login modes ship **off**. Enable them in
**Passkey Settings** after reviewing the resolved Relying Party ID — changing
the RP ID later invalidates every enrolled passkey.

## Development

```bash
cd apps/passkeys
pre-commit install
bench --site <site> run-tests --app passkeys
```

## License

MIT. See `LICENSE`.
