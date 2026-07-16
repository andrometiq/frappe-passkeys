# Proposal 01: pluggable two-factor provider seam

> Design sketch only. Re-read the current `frappe/twofactor.py`, auth imports, login client, and test
> suite before implementing. This document does not claim the current branches expose this contract.

## Goal

Allow core or an app to provide a reviewed non-OTP second-factor method without monkeypatching
import-bound authentication functions, while leaving existing OTP App/SMS/Email behavior unchanged
when no provider is selected.

## Proposed contract

A provider needs three responsibilities:

- `is_configured(user) -> bool`: whether this user can use the selected method;
- `issue(user, tmp_id) -> verification envelope`: create one short-lived challenge; and
- `verify(login_manager, response, tmp_id) -> bool`: consume and verify it before login completes.

The exact hook shape, conflict policy, provider validation, client dispatch, and naming are maintainer
decisions. Provider lookup must reject ambiguous/malformed registrations, and per-user fallback must
not silently downgrade an enrolled passkey user around the app/native passkey policy.

## Implementation checklist

- [ ] Locate issuance and verification in the current core ref, including LDAP and imported aliases.
- [ ] Define a typed provider interface and deterministic duplicate-provider policy.
- [ ] Keep stock OTP paths byte-for-byte equivalent where practical and document every behavior delta.
- [ ] Ensure a verification request cannot re-issue or reuse a challenge.
- [ ] Preserve login tracking, account disable/password rotation checks, session hooks, and envelopes.
- [ ] Add generic client dispatch without trusting provider-controlled HTML or message text.
- [ ] Test provider absent, configured, unconfigured-per-user, malformed, throwing, replayed, expired,
      and concurrent verification cases.
- [ ] Run the complete existing two-factor and authentication suites.

## Passkey-specific warning

A generic provider seam is not sufficient to claim native passkey support. The second-factor login
veto, one-time OTP fallback marker, narrow Administrator exemption, keyed password-hash version, and
transactional credential updates remain mandatory acceptance criteria in
[VALIDATE.md](VALIDATE.md).
