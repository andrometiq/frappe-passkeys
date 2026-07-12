# Install, upgrade, uninstall

This is the self-hoster guide to getting the `passkeys` app onto a Frappe bench,
keeping it current, and removing it safely. Configuration of the login modes
themselves is in [`configuration.md`](configuration.md).

## Supported versions

| Branch | Supported | Why |
|---|---|---|
| **v15** | **v15.107.0 and newer** | The `webauthn` library (2.8.x) requires both `cryptography>=46` and `pyOpenSSL>=26`. v15 bumped `cryptography` in 15.101.0 but only shipped `pyOpenSSL~=26` from **v15.107.0** (2026-04-28). On 15.101.0–15.106.x the dependency resolver cannot satisfy `pyOpenSSL>=26`. Older v15 (cryptography 41.x/44.x) cannot run any usable `py_webauthn` 2.x at all. |
| **v16** | Yes | Ships the required `cryptography` / `pyOpenSSL` pins. |
| **develop** | Yes | Ships newer pins (`cryptography~=48`, `pyOpenSSL~=26.2`). |

The app pins `webauthn>=2.8.0,<3`. The `<3` cap is deliberate: `webauthn` 3.x
needs `cryptography>=49`, which none of the three supported branches ship yet.
Python `>=3.10` is required (v16/develop run 3.14).

The floor is declared in four places that must agree: `pyproject.toml`
(`[tool.bench.frappe-dependencies] frappe = ">=15.107.0,<18.0.0"`), this
documentation, a `before_install` runtime check, and CI.

## Install

```bash
# Pick the branch that matches your Frappe version: version-15, version-16, or develop
bench get-app --branch version-16 https://github.com/Andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
```

`bench get-app` fetches the app and installs its Python requirements (the
`webauthn` wheel). If the wheel is missing later — for example after a manual
checkout — run `bench setup requirements` for the app before enabling any mode;
the Passkey Settings validator refuses to enable passkeys when `webauthn` is not
importable.

**Installing is not enabling.** `install-app` creates the DocTypes and the
`Passkey Settings` single with every login mode **off**. Nothing about
authentication changes until you enable a mode in Passkey Settings — see
[`configuration.md`](configuration.md).

### The `before_install` guards, and what their failures mean

Two checks run in `before_install` (`passkeys/install.py`). This placement is
deliberate: a `before_install` failure leaves **zero** site state, whereas an
`after_install` failure would leave a half-installed, registered app that
re-runs its hooks on every `bench migrate`.

- **Version floor.** If `frappe.__version__` is below 15.107.0, the install
  aborts with:

  > The passkeys app requires Frappe 15.107.0 or newer (found X): the webauthn
  > library needs cryptography>=46.0.0 and pyOpenSSL>=26.0.0, which older
  > releases do not ship.

  Fix: upgrade Frappe (or the whole bench) to a supported version, then retry.
  The `bench get-app` step is unaffected — only `install-app` aborts.

- **Native-core refusal.** If the Frappe you are installing onto already serves
  passkeys natively (the `frappe.passkey` module exists), the install aborts
  with:

  > This Frappe installation serves passkeys natively (frappe.passkey). The
  > passkeys app is an upgrade vehicle for sites that predate the native
  > implementation — it cannot be freshly installed on top of it.

  This is expected on a future Frappe that has adopted the upstream
  implementation. Do not install the app there; use the native feature. A site
  that had the app installed *before* upgrading is migrated by core's adoption
  patch and does not hit this path.

## Site configuration, reverse proxy, RP-ID and origin

A passkey is bound to a **Relying Party ID (RP ID)** — a bare host name — and to
a set of exact **origins**. These are resolved once, at enable time, from pinned
configuration; the app never derives them from the live `Host` or
`X-Forwarded-*` request headers. Two consequences for deployment:

- **`host_name` must be set in site config** (or set Passkey RP ID explicitly).
  When Passkey RP ID is left blank, the default RP ID is the **exact host** of
  the site's configured `host_name` (for example `app.example.com`) — never a
  parent/registrable domain. If neither `host_name` nor Passkey RP ID resolves,
  enabling a mode fails validation. On multi-tenant shared-suffix hosting, the
  per-site host is the RP ID; it is never the shared base domain.

- **The public host the browser sees must match the RP ID and origins.** Behind
  a reverse proxy or load balancer:
  - Terminate TLS at, and serve from, the public host that equals the RP ID.
    Passkeys require **HTTPS**; `http://` origins are rejected except
    `http://localhost` while `developer_mode` is on.
  - Ensure the browser reaches the site on exactly that host. The default
    origins are `https://<rp_id>`; add any additional exact origins (including
    explicit ports, one per line) in Passkey Settings → Passkey Origins. Every
    listed origin's host must equal the RP ID or be a subdomain of it — an
    out-of-scope origin passes every server check and then dies client-side with
    a permanent browser `SecurityError`, so the settings validator refuses it.
  - Serving the same site under multiple unrelated domains needs Related Origin
    Requests, which this version does not implement.

If a request arrives on a host that is not among the configured origins, the
begin ceremony fails closed, writes a structured log line
(`passkeys: request host … not in configured origins`), and the Passkey Settings
page shows a red mismatch banner — fail-closed is always diagnosable. See
[`operations.md`](operations.md) for the host-change playbook.

## Upgrade

```bash
bench update --apps passkeys        # or your normal bench update flow
bench --site <site> migrate
```

`bench migrate` runs the app's `after_migrate` hook, which re-syncs a small
System Settings property setter used by the pluggable-two-factor integration, and
applies any pending `patches.txt` migrations. The current patch folds a legacy
site's `passkey_enrollment_nudge` boolean into the `passkey_enrollment_policy`
adoption ladder and seeds the break-glass exempt role; it is idempotent and never
clobbers a policy an administrator has already chosen. No settings are otherwise
changed by an upgrade; enabled modes stay enabled.

## Disable vs uninstall

**Disable** (turn the modes off in Passkey Settings) is the reversible pause:
all passkey UI disappears, the login and second-factor ceremonies refuse, but
every credential row is preserved and the action-confirmation primitive keeps
working. Re-enabling restores everything. Prefer this for temporary changes.

**Uninstall** drops the app's DocTypes and their tables. On its own that would
destroy every stored credential and orphan the passkeys held on users'
authenticators (the server-side public key they matched would be gone). To make
removal recoverable, `before_uninstall` **exports every credential first** (see
"Credential export on uninstall" below), so an uninstall is a reversible move
rather than a one-way delete. Still, only uninstall when you mean it.

## Uninstall

```bash
bench --site <site> uninstall-app passkeys
```

`before_uninstall` **blocks** the removal — with a remediation message — in two
lockout cases, so you cannot strand your users by accident:

- **Site-wide password login is disabled and no other method survives.** If
  `disable_user_pass_login` is on and none of Social Login, LDAP, or Login With
  Email Link is enabled, removing passkeys would leave no way in. Enable one of
  those in System Settings first.

- **Passkey-only users exist.** If any user has *Passkey Only Login* set on
  their WebAuthn User Handle, they would be locked out. Clear that flag on the
  listed users first (WebAuthn User Handle list in Desk, or `bench console` —
  see [`recovery.md`](recovery.md)).

Once the guards pass, uninstall also deletes the app's per-user nudge state and
its property setter, so a later reinstall is a clean slate. Cached challenge /
grant / sudo state in Redis expires on its own.

### Credential export on uninstall

Because dropping the tables would otherwise destroy every enrolled passkey,
`before_uninstall` first writes **all** `WebAuthn Credential` and `WebAuthn User
Handle` rows to a single JSON file, then prints its path in the uninstall output:

```
passkeys: credentials exported before uninstall -> .../private/files/passkeys-credentials-YYYYMMDD-HHMMSS.json
passkeys: to restore them after reinstalling, run in `bench --site <site> console`:
passkeys:   from passkeys.install import import_credentials; import_credentials("<path>")
```

- **Where it lands.** The site's private files —
  `sites/<site>/private/files/passkeys-credentials-<timestamp>.json`. It is not a
  web-served public file. The export is skipped (no file, nothing printed) when
  there are no credentials to save.
- **What it contains.** Public-key material and metadata only — the credential
  public keys, signature counters, backup flags, labels, transports, AAGUID, and
  the opaque user handles with each user's *Passkey Only Login* flag. **No server
  secret exists in either table**, so the file is safe to keep alongside a site
  backup; a public key is useless to an attacker who obtains it.

**Restore (reinstall on the same site).** Reinstall the app, then replay the file:

```bash
bench --site <site> install-app passkeys
bench --site <site> console
>>> from passkeys.install import import_credentials
>>> import_credentials("sites/<site>/private/files/passkeys-credentials-<timestamp>.json")
{'credentials_created': 4, 'credentials_skipped': 0, 'handles_created': 3, 'handles_skipped': 0}
```

`import_credentials` is **idempotent**, keyed on `credential_id_sha256` for
credentials and on `user` for handles: a row that already exists is skipped, so
re-running is safe and never duplicates. Signature counters are restored verbatim
(never reset to zero), and credentials are restored before handles so a
`Passkey Only Login` handle clears its "needs an enabled passkey" floor. The
authenticators users still hold keep working against the restored public keys —
no re-enrollment.

**Core-handoff note (honest).** When a future Frappe serves passkeys natively,
this same export is the **migration seed** — the durable, secret-free record of
every credential a site had. The exact field-to-field mapping into core's schema
is deliberately *not* written yet: it will be authored once that schema actually
exists, so the mapping matches reality instead of a guess. Until then, keep the
export file if you plan to adopt the native feature later.
