# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project has not published a stable
release.

## [Unreleased]

### Added

- Final-login enforcement for enrolled passkey second-factor users, including alternate core login
  paths and a one-time, user-bound OTP fallback handoff.
- Database serialization for credential verification, UV completion, registration caps,
  passkey-only account floors, and passkey-mode changes.
- Site-bound, HMAC-authenticated credential exports with atomic private-file writes and strict
  restore validation.
- Explicit action labels and safe parameter summaries for passkey confirmation dialogs.
- Shared, site-scoped action policy publication for deterministic confirmation across workers.
- Pinned-input release CI, data-bearing lifecycle checks, JavaScript unit gates, secret scanning,
  and a separate moving-upstream compatibility workflow whose failures remain visible.
- Release checklist and private security-reporting policy.

### Changed

- RP IDs no longer imply trust in `https://<rp_id>`. Only a compatible configured `host_name`
  origin and explicitly listed Passkey Origins are accepted. **Action required before upgrading an
  already-enabled site:** confirm `host_name` or an explicit Passkey Origin resolves within the RP
  ID scope first, or the resolved origin set can become empty and every ceremony fails closed (a
  generic sign-in error for users, with a structured log line for operators) until the settings
  are fixed — see the [upgrade note](docs/install.md#upgrade).
- Administrator remains exempt from the per-user passkey-only password veto, but an Administrator
  enrolled in passkey second-factor mode must complete that factor.
- Passkey second-factor ceremonies detect password changes between legs without normally retaining
  the password in ceremony state.
- Enforcement deferrals are idempotent per user session.
- Android certificate fingerprints must contain exactly 64 hexadecimal characters.
- Native-core dormancy now requires an explicit handover capability marker; module presence alone
  cannot silence an installed app.
- Browser management, confirmation, headless, portal, recovery, and unsupported-device states now
  use the same server-owned contracts.
- Legacy unsigned credential exports require an explicit, operator-reviewed import opt-in.

### Security

- Test-only WebAuthn helpers require a test runner, or a System Manager on a site with both
  `developer_mode` and `allow_tests` enabled; all helper endpoints are POST-only.
- Assertion counters are reclassified under row locks before sessions or grants are minted,
  rejecting duplicate nonzero counter replays.
- Credential import refuses unsigned files by default, modified or cross-site v2 files,
  structurally inconsistent rows, and unreviewed live-data merges.
- Minimum supported Frappe is a per-major-line floor (v15 ≥ 15.108.0, v16 ≥ 16.18.3) that excludes
  releases exposed to CVE-2026-47194 (host-header poisoning of magic/passwordless login links);
  enforced by the `before_install` version check.

[Unreleased]: https://github.com/Andrometiq/frappe-passkeys/compare/develop...HEAD
