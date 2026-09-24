# Install, upgrade, uninstall

This is the self-hoster guide to getting the `passkeys` app onto a Frappe bench,
keeping it current, and removing it safely. Configuration of the login modes
themselves is in [`configuration.md`](configuration.md).

## Supported versions

| Branch | Supported | Why |
|---|---|---|
| **v15** | **v15.108.0 and newer** | Use `version-15`. |
| **v16** | **v16.18.3 and newer** | Use `version-16`. |
| **develop** | Integration target | Pre-release only. Moving branch-tip CI fails visibly on drift but is not a release or production-readiness attestation. |

The app pins `webauthn==2.8.0`; changing that authentication-critical dependency requires the full
resolver and ceremony matrix. Python `>=3.10,<3.15` is declared. These constraints describe what the
candidate accepts, not a promise that every future Frappe patch release in the range is compatible.

`pyproject.toml` declares the Frappe range (`[tool.bench.frappe-dependencies] frappe =
">=15.108.0,<18.0.0"`). Release CI validates a reviewed, pinned Frappe baseline per branch; validate
the exact Frappe patch level you deploy.

## Install

```bash
# Pick the branch that matches your Frappe version: version-15, version-16, or develop
bench get-app --branch version-16 https://github.com/Andrometiq/frappe-passkeys
bench --site <site> install-app passkeys
```

`bench get-app` fetches the app and installs its Python requirements (the
`webauthn` wheel). If the wheel is missing later — for example after a manual
checkout — run `bench setup requirements` for the app before enabling any mode;
the Passkey Settings validator checks package presence on enabled settings saves. When either
login mode changes from off to on, it also verifies that the ceremony engine imports successfully
in a bounded child process using the bench's Python interpreter. A failure refuses the save;
crypto is never loaded into the serving worker by this check. Ordinary saves of already-enabled
modes and mode disabling do not launch the probe. This is an enablement-time check, not ongoing
dependency or worker-health monitoring.

**Installing is not enabling.** `install-app` creates the DocTypes and the
`Passkey Settings` single with every login mode **off**. Nothing about
authentication changes until you enable a mode in Passkey Settings — see
[`configuration.md`](configuration.md).

### The `before_install` guard

`before_install` (`passkeys/install.py`) refuses the install in one case. It runs before install
so a refusal leaves **zero** site state.

- **Native-module refusal.** If the Frappe tree contains a `frappe.passkey` module, the install aborts
  with:

  > This Frappe installation serves passkeys natively (frappe.passkey). The
  > passkeys app is an upgrade vehicle for sites that predate the native
  > implementation — it cannot be freshly installed on top of it.

  Module presence prevents two fresh authorities from being installed together, but it does **not**
  prove that core implements this app's runtime handover contract. For an already-installed app to
  become dormant safely, `frappe.passkey` must also define the exact marker
  `FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`. Without that marker, the app
  stays active. No current core adoption patch is assumed; follow the proposal and validation
  checklist in [`upstream/`](upstream/) for any future migration.

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
  - Ensure the browser reaches the site on exactly that host. The exact origin parsed from a
    compatible `host_name` is trusted automatically. **The RP ID never creates an implicit
    `https://<rp_id>` origin.** Add every other exact origin (including
    explicit ports, one per line) in Passkey Settings → Passkey Origins. The resolved set must not
    be empty. Every
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
cd apps/passkeys && git pull --ff-only && cd ../..
bench build --app passkeys
bench --site <site> migrate
bench restart
```

Building *before* migrating is deliberate: migrate's cache flush then also picks up
the freshly built asset map. (`bench build`'s own Redis invalidation can fail
silently — if the UI looks stale after an upgrade, run
`bench --site <site> clear-cache && bench --site <site> clear-website-cache`.)

`bench migrate` runs the app's `after_migrate` hook, which syncs the User-form passkey section. An
upgrade changes no settings; enabled modes stay enabled.

Do not promote an upgrade from this command sequence alone: back up the database and private
files, validate on staging behind your real proxy and origins, and have a tested recovery path — see
[Operations](operations.md#before-you-enable-passkeys-on-a-production-site).

## Disable vs uninstall

**Disable** (turn the modes off in Passkey Settings) is the reversible pause:
all passkey UI disappears, the login and second-factor ceremonies refuse, but
every credential row is preserved and the action-confirmation primitive keeps
working. Re-enabling restores the modes. This suspends the site's passkey login
controls; it is not an account-recovery procedure. Use [Desk recovery](recovery.md)
for lockouts, and reserve disabling controls for its warned last resort.

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
  listed users through their **WebAuthn User Handle** forms in Desk and verify
  their replacement sign-in methods before removal. If a user is locked out,
  follow [account recovery](recovery.md#a-user-lost-their-passkey) first.

Once the guards pass, uninstall also deletes the app's per-user nudge state and the User-form
passkey section, so a later reinstall is a clean slate. Cached challenge /
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
- **Format and integrity.** The current format is schema version **2**, bound to the originating
  site name and authenticated with **HMAC-SHA256** using a key derived from that site's
  `encryption_key`. It is not portable to another site or to a replacement encryption key. The file
  is written through a same-directory temporary file, `fsync`ed, atomically replaced, and forced to
  mode `0600`. A data-bearing uninstall/export refuses to proceed when the site has no
  `encryption_key`; confirm the key exists in `site_config.json` before enrolling production users.
- **What it contains.** Public-key material and metadata — the credential
  public keys, signature counters, backup flags, labels, transports, AAGUID, and
  the opaque user handles with each user's *Passkey Only Login* flag. **No server
  secret exists in either table**, but labels, user references, and authenticator metadata may still
  be sensitive. Protect and retain the file like the matching site backup; the matching
  `encryption_key` is required to verify it.

**Restore (reinstall on the same site).** The export carries no Passkey Settings, and a passkey
only works under the RP ID it was created for. Before uninstalling, record the site's Passkey RP
ID, Passkey Origins and Trusted App Origins. Reinstall the app, restore those values through a
validated settings save, then replay the file:

```bash
bench --site <site> install-app passkeys
bench --site <site> console
>>> import frappe
>>> settings = frappe.get_single("Passkey Settings")
>>> settings.passkey_rp_id = "<the recorded RP ID; blank if it was blank>"
>>> settings.passkey_origins = "<the recorded origins, one per line>"
>>> settings.passkey_app_origins = "<the recorded trusted app origins, if any>"
>>> # Enable a passkey login mode before importing passkey-only users — otherwise the
>>> # restore refuses (those users would be locked out):
>>> settings.login_with_passkey = 1
>>> settings.save()
>>> frappe.db.commit()
>>> from passkeys.install import import_credentials
>>> import_credentials("sites/<site>/private/files/passkeys-credentials-<timestamp>.json")
{'credentials_created': 4, 'credentials_skipped': 0, 'handles_created': 3, 'handles_skipped': 0}
```

The enable-a-mode step is only required when the export carries *Passkey Only Login* users; for a
plain restore it is harmless (re-enabling the mode you were already running). The RP ID and origins
are not optional: under a different RP ID every restored passkey fails to authenticate. By default,
`import_credentials` requires **both passkey tables to be empty**. This makes an
accidental import into a live credential set fail before merging anything. `allow_existing=True` is
an explicit, operator-reviewed merge mode, not an idempotency convenience: inspect handle ownership
and credential conflicts before using it. Matching rows are skipped, inconsistent or disabled-user
rows are rejected and reported, and valid rows may still be imported. Signature counters are
restored verbatim (never reset to zero), and credentials are restored before handles. On a clean,
same-site restore under the original RP ID, authenticators users still hold continue to match the
restored public keys.

**Possible core-handoff input.** The export may be useful as a migration input for a future native
implementation, but no current core schema or compatible importer is claimed. A future adoption
must define and test the field mapping, preserve counters and ownership, and advertise the exact
handover marker before the app can yield safely.
