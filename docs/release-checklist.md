# Release Checklist

A green branch is not automatically production-ready. Complete this checklist for the exact commit
and deployment target being released. Record evidence in the release or change ticket.

## Candidate

- [ ] Select one immutable app commit; confirm the worktree is clean and review the full diff from
      the previous release candidate.
- [ ] Record the exact Frappe commit or tag, Python, Node, MariaDB, Redis, browser, and WebAuthn
      dependency versions used for validation.
- [ ] Confirm the candidate's Frappe and Python versions satisfy `pyproject.toml` and the install
      guard.
- [ ] Confirm the target site's `encryption_key` exists, is backed up separately, and remains
      available for credential-export verification and restore.
- [ ] Review `CHANGELOG.md`, upgrade notes, configuration docs, recovery docs, and API contracts for
      this candidate.

## Automated Gates

- [ ] Lint, formatting, Python 3.10 syntax-floor compilation, and hook-path import checks pass.
- [ ] The complete server suite passes on each supported pinned Frappe baseline.
- [ ] Every JavaScript unit spec is discovered and passes on the supported Node versions.
- [ ] Cypress runs with CSRF enabled, test isolation enabled, retries disabled, and no swallowed
      browser exceptions on each supported Frappe baseline.
- [ ] Clean install, migrate, uninstall, reinstall, and post-reinstall migrate succeed.
- [ ] Secret and private-data scans of the worktree and reachable history are clean or every finding
      is reviewed and documented.
- [ ] The moving-upstream workflow is green and has been reviewed for drift; its branch-tip result
      is not treated as an attestation for the selected release candidate.

## Security Review

- [ ] Review every authentication and confirmation endpoint for authorization, HTTP method, CSRF,
      rate limiting, session binding, origin binding, one-time state, and uniform failure behavior.
- [ ] Verify test-only endpoints are unavailable unless the test runner is active, or the caller is a
      System Manager and both `developer_mode` and `allow_tests` are enabled.
- [ ] Re-run concurrency tests for sign counters, registration caps, credential deletion, passkey-only
      flags, settings mode changes, and grace accounting.
- [ ] Review dependency changes and published security advisories for Frappe, `webauthn`,
      `cryptography`, Redis, MariaDB, Node, Cypress, and the selected browser.
- [ ] Audit both the built app wheel's resolved runtime dependencies and the complete deployment
      bench. Treat an unresolved host-framework advisory as a release blocker or record the exact
      owner-approved exception, exposure analysis, and compensating control.
- [ ] Complete an independent correctness, security, and documentation-conformance review of the
      candidate diff; resolve or explicitly accept every finding.

## Staging

- [ ] Build a fresh staging site on the production TLS, reverse-proxy, host, port, and worker layout.
- [ ] Set `host_name`, RP ID, exact Passkey Origins, and any native-app origins. Confirm the settings
      page displays the same origin set used by ceremonies.
- [ ] Test registration, explicit passwordless login, conditional login, credential rename/delete,
      passkey-only enable/disable, action confirmation, logout, and session expiry.
- [ ] Test platform and roaming authenticators, synced and device-bound credentials, UV-present and
      UV-absent responses, cancellation, timeout, replay, disabled users, and revoked credentials.
- [ ] In second-factor mode, test password changes between legs, OTP fallback on and off, direct core
      OTP attempts, and every enabled alternate login path.
- [ ] Test enforcement on capable and incapable devices, distinct and repeated tabs, grace exhaustion,
      exemptions, administrator recovery actions, and mail notifications.
- [ ] Verify French and default-language login, management, confirmation, errors, keyboard navigation,
      focus handling, screen-reader labels, and mobile layouts.
- [ ] For native apps, validate the deployed Android Asset Links and Apple App Site Association files
      from outside the private network.

## Backup And Recovery

- [ ] Take and restore a normal site backup before enabling passkeys.
- [ ] Exercise the credential export, verify mode `0600`, reject a modified or cross-site copy, and
      restore into an empty test installation using the documented command. If a legacy schema-v1
      file is required, verify default rejection and record the review that justified the explicit
      `allow_unsigned_legacy=True` opt-in.
- [ ] Rehearse recovery for a lost only authenticator, a passkey-only user, an enrolled Administrator,
      broken origins/RP ID, disabled OTP fallback, unavailable Redis, and an app rollback.
- [ ] Confirm at least two authorized operators can execute the console recovery procedure without
      relying on the affected login path.

## Release And Rollout

- [ ] Tag the reviewed commit; do not move the tag after validation.
- [ ] Publish the changelog, supported version scope, known limitations, upgrade steps, and rollback
      steps with the release.
- [ ] Roll out first to a bounded cohort with password login retained; monitor authentication errors,
      fallback events, sign-counter flags, enrollment failures, and support load.
- [ ] Enable passkey-only or enforcement policies only after the observation window and recovery drill
      succeed.
- [ ] Record final maintainer sign-off for security, operations, and rollback readiness.
