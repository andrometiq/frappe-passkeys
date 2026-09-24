# Security Policy

## Supported Versions

| Branch | Release line | Security fixes |
| --- | --- | --- |
| `version-16` | 16.x (Frappe v16) | Yes |
| `version-15` | 15.x (Frappe v15) | Yes |
| `develop` | Integration branch | Fixed here first; not for production |

Fixes land on `develop` and ship in the next 15.x / 16.x release. Validate a release against your
exact Frappe version and topology before enabling it
([Operations](docs/operations.md#before-you-enable-passkeys-on-a-production-site)).

## Reporting A Vulnerability

Do not disclose vulnerabilities, credentials, user data, or exploit details in a public issue.

Use GitHub's private vulnerability reporting entry on this repository's **Security** tab. Include:

- the affected app commit and Frappe version;
- configuration and deployment topology relevant to the issue;
- reproducible steps or a minimal proof of concept;
- impact, required attacker access, and any known mitigations; and
- whether the issue is already public or under active exploitation.

If private vulnerability reporting is unavailable, open a public issue containing only a request
for a private maintainer contact. Do not include technical details in that issue.

Maintainers will acknowledge receipt, reproduce and classify the report, coordinate a fix and
release plan, and credit the reporter when requested. This is a community project without a
commercial support contract, so no response-time SLA is promised.

## Scope

Authentication bypasses, ceremony or origin-validation flaws, account lockout, cross-user access,
credential lifecycle corruption, unsafe migration/export behavior, and production-reachable test
facilities are in scope. Findings that require a site to deliberately enable both `developer_mode`
and `allow_tests` are still useful, but should state that prerequisite clearly.

General hardening suggestions without a concrete security impact may be filed as normal issues.
