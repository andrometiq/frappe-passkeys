# Proposal: adopting passkeys in `frappe/frappe`

> **Status: design proposal, not a compatibility statement.** Nothing in this directory means that
> a current Frappe branch contains the required extension points, schema, migration, or handover
> contract. Before opening an upstream PR, rebase onto the then-current `develop`, inspect the real
> code, replace sketches with a tested diff, and complete [`VALIDATE.md`](VALIDATE.md).

This directory breaks possible core adoption into reviewable decisions. It intentionally avoids
pinned commit hashes, line numbers, patch sizes, test counts, and claims that existing core behavior
is identical. Those facts expire quickly and must be recorded in the eventual PR with an explicit
date and ref.

## Proposed sequence

1. **Confirm current core architecture.** Map login, two-factor dispatch, System Settings,
   `/.well-known/` routing, session minting, hooks, templates, and test infrastructure at the target
   ref. Treat every document here as input, not proof.
2. **Agree on schema and ownership.** Core maintainers choose module placement, DocType names,
   System Settings fields, public API names, and whether a generic two-factor provider registry is
   desirable.
3. **Land the smallest prerequisite seams.** The sketches cover a two-factor provider interface,
   password-disable validation, a native login-page slot, and the `webauthn` autocomplete token.
   These may be changed, combined, or rejected during review.
4. **Build native passkeys from the hardened contracts.** Port behavior, not files blindly. The
   app's hooks and released-branch shims are not automatically suitable for core.
5. **Prove migration and handover.** Test an app-installed site with real credential/settings data,
   then test the installed app and native core together before advertising dormancy.
6. **Release incrementally.** Keep the app authoritative until a released core version has passed
   the migration, coexistence, rollback, and recovery gates.

## Non-negotiable contract checklist

Any native proposal must preserve or deliberately supersede these app guarantees:

- RP ID is credential scope, not origin authorization. Exact web origins come from a compatible
  `host_name` plus explicit Passkey Origins; the set cannot be empty. iOS `https://<rp_id>` must be
  explicitly present when used.
- Administrator is break-glass exempt only from the per-user passkey-only login veto. An
  Administrator enrolled for passkey second factor is protected like any enrolled user.
- Enrolled second-factor users cannot complete password, email-link, social/OAuth, LDAP, or other
  core login paths unless the passkey completed or the app issued the one-time OTP marker.
- Password rotation is detected before session minting with a keyed, non-reversible password-hash
  version.
- Credential verification/counters, UV setup, registration/caps, passkey-only floors, and settings
  transitions are transactionally locked.
- Uninstall export v2 is site-bound HMAC-SHA256, atomically written at mode `0600`; default import
  requires empty tables and `allow_existing=True` is a reviewed merge.
- Android fingerprints are exact SHA-256 values; association responses cache for one hour.
- Enrollment grace defer is claimable once per session.
- Installed-app dormancy requires exactly
  `FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"`. `frappe.passkey` presence alone
  may block a fresh install but must not silence an installed app.
- Confirmation UI metadata uses explicit `display_label` and `display_params`; display parameters
  are a subset of bound parameters and never change grant binding.
- Production readiness is established per release candidate by the release checklist, not inferred
  from this proposal or a moving branch-tip test.

## Proposed work packages

| Package | Purpose | Document |
|---|---|---|
| Two-factor provider seam | Let a reviewed provider issue and verify a non-OTP second factor without monkeypatching | [`patch-01-two-factor-methods-registry.md`](patch-01-two-factor-methods-registry.md) |
| Password-disable validator | Count native passkey login as a surviving method only when the native feature and fields exist | [`patch-02-disable-user-pass-login-validator.md`](patch-02-disable-user-pass-login-validator.md) |
| Native login surface | Render and initialize passkeys without DOM-injection shims | [`patch-03-login-page-context-template.md`](patch-03-login-page-context-template.md) |
| Conditional UI token | Add `webauthn` to the username autocomplete contract | [`patch-04-autocomplete-webauthn-token.md`](patch-04-autocomplete-webauthn-token.md) |
| Settings placement | Decide whether passkey settings fold into System Settings or stay a linked single | [`patch-05-system-settings-placement.md`](patch-05-system-settings-placement.md) |
| Enrollment-scoped email links | Bootstrap passkey setup on password-disabled sites via a purpose-scoped magic link | [`patch-06-enrollment-scoped-email-link.md`](patch-06-enrollment-scoped-email-link.md) |
| App-to-core inventory | Decide port/fold/replace/discard per component at PR time | [`mapping.md`](mapping.md) |
| Acceptance gates | Rebase, security, migration, coexistence, rollback, and release checks | [`VALIDATE.md`](VALIDATE.md) |

## Handover boundary

The marker is a promise by core, not feature detection:

```python
FRAPPE_PASSKEYS_APP_HANDOVER = "frappe-passkeys-app-handover-v1"
```

Core must not define it until its implementation has passed the complete coexistence and migration
suite. The app's fresh-install guard is intentionally more conservative: any `frappe.passkey`
module blocks a new install to prevent two fresh authorities. That guard does not make a partial
module a safe automatic handover for existing sites.

## Prior work

Historical Frappe issues and PRs can inform design, but their status and review conclusions must be
checked live before citing them in a PR. Do not describe a closed or stale proposal as approved
without a current maintainer decision.
