# Upstream adoption validation checklist

This checklist defines evidence required before claiming that a core patch is compatible with the
app or that an installed app can yield to core. It is not evidence that the checks currently pass.

## 1. Pin and map

- [ ] Record the app commit, core commit, Frappe version, Python, Node, database, browser, and date.
- [ ] Re-read the target core auth, two-factor, settings, routing, session, and login UI code.
- [ ] Replace every sketch in this directory with a rebased diff; do not apply old line-number patches.
- [ ] Inventory all app hooks, endpoints, routes, DocTypes, defaults, cache keys, assets, and lifecycle
      hooks from the actual tree.
- [ ] Resolve schema, module ownership, API names, and backport policy with maintainers.

## 2. Existing-core regression gates

- [ ] Existing password, email-link, OAuth/social, LDAP, OTP App, SMS, and Email login suites pass
      with no passkey provider configured.
- [ ] Provider resolution fails closed on malformed, duplicate, missing, or throwing providers.
- [ ] Existing login envelopes, password reset, account disable, login tracking, impersonation,
      session hooks, CSRF, and rate limits remain intact.
- [ ] The password-disable validator refuses a no-surviving-method configuration and accepts native
      passkey login only when the corresponding native feature is actually available.
- [ ] Login markup and conditional UI are covered by server assertions plus a real browser smoke test;
      browser retry settings do not conceal assertion-level failures.

## 3. Passkey security contracts

- [ ] No username/credential enumeration is introduced at first-factor begin.
- [ ] Exact origins resolve only from compatible `host_name` plus explicit origins; empty is invalid;
      RP ID does not synthesize `https://<rp_id>`; iOS exact-origin behavior is tested.
- [ ] Binder, challenge, confirmation grant, OTP fallback marker, and grace-defer claims are atomic and
      single-use across workers.
- [ ] Passwordless and confirmation UV rules are enforced from authenticator data.
- [ ] Sign-count replay/regression and backup-flag policies preserve upward-only state under races.
- [ ] Password+passkey ceremonies reject password rotation through a keyed non-reversible version.
- [ ] Enrolled second-factor users are vetoed on password, email-link, social/OAuth, LDAP, direct OTP,
      and other core completion paths unless native passkey or the one-time fallback marker succeeded.
- [ ] Administrator is exempt only from passkey-only login; an enrolled second-factor Administrator
      is covered by the same veto.
- [ ] Registration, credential/UV writes, credential floor, and settings transitions are tested with
      real concurrent transactions.
- [ ] `display_params` cannot expose unbound arguments and display metadata cannot weaken grant binding.

## 4. Data migration and recovery

- [ ] Exercise an app-installed site containing multiple users/credentials, counters, backup/UV state,
      flags, non-default settings, role child rows, and nudge/grace state.
- [ ] Verify row counts and field-by-field values before/after migration without relying on matching
      DocType names.
- [ ] Verify child rows are re-parented/transformed with no orphans or duplicates.
- [ ] Re-run the adoption patch to prove idempotency.
- [ ] Test backup restore, rollback to app authority, and recovery from a failed mid-upgrade migration.
- [ ] Verify export v2 HMAC/site binding, `0600` atomic output, empty-table default import, rejection
      reporting, and an explicitly reviewed `allow_existing=True` merge.

## 5. Native association and browser surfaces

- [ ] Android accepts only exact SHA-256 signing-certificate fingerprints and uses the delivered app-
      signing certificate.
- [ ] iOS `https://<rp_id>` is present in the exact origin allowlist when asserted.
- [ ] Both association files return bare JSON, `200`, no redirect, correct content type, and
      `Cache-Control: public, max-age=3600`; incomplete settings return `404`.
- [ ] Web, iOS, and Android cross-surface registration/assertion are tested on target devices.
- [ ] Login, management, confirmation, enrollment, accessibility, translations, and no-WebAuthn
      degradation are tested in supported browsers.

## 6. Handover and coexistence

- [ ] With `frappe.passkey` present but no marker, a fresh install is refused and an already-installed
      app remains active.
- [ ] Core defines `FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"` only in the
      validated implementation.
- [ ] With the marker present, every app hook is inert and every app endpoint follows the documented
      `417 PasskeyServedByCore` contract; enumerate dynamically rather than pinning a count here.
- [ ] Prove there is one login veto, one credential writer, one sudo/grant authority, one route/UI,
      one association-file owner, and one session-minting path.
- [ ] Uninstall the dormant app, then verify native login, recovery, and credentials again.

## 7. Release claim

- [ ] All required core CI and security/static-analysis gates pass at the recorded commit.
- [ ] The exact app-to-core upgrade is validated on a production-like staging topology.
- [ ] Changelog, migration, rollback, recovery, and security-reporting docs are reviewed.
- [ ] The claim states the tested refs and scope. A moving branch-tip pass is never described as a
      release gate or global compatibility proof.
