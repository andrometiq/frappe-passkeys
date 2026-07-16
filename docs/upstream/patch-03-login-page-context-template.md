# Proposal 03: native login-page passkey surface

> Design sketch only. Core login markup and JavaScript move over time; inspect the target ref and
> choose native extension points with maintainers before writing the diff.

## Goal

Render and initialize passkey first-factor, conditional UI, and second-factor prompts without the
app's DOM-injection shim, while preserving core login envelopes, accessibility, translations, and
non-passkey behavior.

## Checklist

- [ ] Add a server-authoritative enablement/config channel without leaking account existence.
- [ ] Render an accessible passkey control in the current login component/template.
- [ ] Load the native bundle only when appropriate and support no-WebAuthn degradation.
- [ ] Arm conditional mediation at the current documented lifecycle point.
- [ ] Keep begin/get/verify in one first-party context so the binder cookie and exact origin hold.
- [ ] Use the final native endpoint names and typed errors; do not retain app endpoint aliases by
      accident.
- [ ] Integrate second-factor dispatch through the accepted core design, including the alternate-path
      veto and one-time OTP fallback marker.
- [ ] Test password reset, email-link/social/LDAP, OTP, translations, keyboard/screen-reader behavior,
      conditional UI, explicit button, cancellation, retry, and session redirect.

Server tests must carry assertion-level security proof. Browser tests are required smoke/integration
evidence, not the sole proof of additivity.
