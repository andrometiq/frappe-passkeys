# Proposal 06: enrollment-scoped email links for passkey bootstrap

> Design sketch only. Re-read the current magic-link login implementation (`login_via_key` and its
> host-header hardening) before implementing.

## Goal

On a site with password login disabled, a user who has no passkey yet still needs a first sign-in
to enroll one. Core's existing email-link login already solves the sign-in; what core can add
natively — and an app cannot cleanly — is a link whose session is scoped to enrollment.

## Why the app ships nothing here

The composed flow works today with zero new machinery: enable core's `login_with_email_link`, the
user signs in through it, and the app's enrollment policy (nudge or enforce interstitial) walks
them into passkey setup. A standalone app feature would re-implement core's link minting, mail
delivery, expiry, and rate limiting — a security-sensitive surface core hardened for
host-header poisoning (CVE-2026-47194) — only to add session scoping. That scoping is the
native seam.

## Proposed change

Give core's magic-link login an optional purpose scope. An enrollment-scoped link signs the user
into a session that can only complete passkey enrollment (and the sign-out that follows), not act
as a general session. Admins and users can then send "set up your passkey" links that are safe to
issue more freely than full login links. Link generation must use the pinned origin set, never
request headers.

## Checklist

- [ ] Confirm the current `login_via_key` flow, its rate limits, and the CVE-2026-47194 hardening
      at the target ref.
- [ ] Add a purpose scope to link minting and session creation; default remains a full login link.
- [ ] Enforce the scope server-side on every request in the scoped session; fail closed.
- [ ] Reuse the existing enrollment surfaces to complete setup inside the scoped session.
- [ ] Test: scoped link cannot reach any non-enrollment endpoint; expiry, single-use, and
      rate-limit parity with login links; origin pinning on generated URLs.

No current-core compatibility is claimed until these checks pass at a recorded commit.
