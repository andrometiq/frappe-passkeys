# Security Policy

## Supported Versions

| Branch | Release line | Security fixes |
| --- | --- | --- |
| `version-16` | 16.x (Frappe v16) | Yes |
| `version-15` | 15.x (Frappe v15) | Yes |
| `develop` | Integration branch | Fixed here first; not for production |

Fixes land on `develop` and ship in the next 15.x / 16.x release.

## Reporting A Vulnerability

Do not disclose vulnerabilities, credentials, user data, or exploit details in a public issue.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting form](https://github.com/Andrometiq/frappe-passkeys/security/advisories/new),
and include:

- the affected app commit and Frappe version;
- configuration and deployment topology relevant to the issue;
- reproducible steps or a minimal proof of concept;
- impact, required attacker access, and any known mitigations; and
- whether the issue is already public or under active exploitation.

## What Happens Next

- High and critical issues are fixed on both release lines within 30 days of your report. Other
  issues are fixed in a later release.
- Each fix gets a GitHub security advisory naming the affected and fixed versions of each line, and
  credits you if you want.

## Scope

Authentication bypasses, ceremony or origin-validation flaws, account lockout, cross-user access,
credential lifecycle corruption, unsafe migration/export behavior, and production-reachable test
facilities are in scope. Findings that require a site to deliberately enable both `developer_mode`
and `allow_tests` are still useful, but should state that prerequisite clearly.

General hardening suggestions without a concrete security impact may be filed as normal issues.

## Not A Vulnerability

These are by design; see [docs/security.md](docs/security.md).

- Requests made with an API key or an OAuth token skip passkey sign-in checks, as they skip
  Frappe's own two-factor authentication.
- A required passkey is a prompt after sign-in, not a server-side block: a client that never runs
  the app's JavaScript is not stopped by it.
- An administrator can change a user's passkeys from their own session. The impersonation lock
  only stops accidental or hidden changes.
- Anything that needs `bench console`, direct database access or the server's shell.
- Attacks that need control of a subdomain inside the site's RP ID, or of the user's device or
  passkey provider.
- Bugs in Frappe itself: report those to [Frappe](https://frappe.io/security).
