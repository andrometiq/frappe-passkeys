# Proposal 04: add the WebAuthn autocomplete token

> Design sketch only. Confirm the current login input and form ownership at the target core ref.

## Goal

Conditional passkey UI requires the username input used by the active login form to include the
`webauthn` autocomplete token:

```html
<input autocomplete="username webauthn">
```

## Checklist

- [ ] Apply the token to the real username field in every active login markup generation.
- [ ] Preserve existing username autofill and accessibility semantics.
- [ ] Confirm browsers without conditional mediation ignore the extra token safely.
- [ ] Test rendered HTML and a real conditional-UI ceremony when the native bundle is armed.
- [ ] Do not treat this token as native passkey support by itself; without the server ceremony,
      exact-origin policy, and login integration it is inert.

Whether this lands independently or with the native login surface is a maintainer/release decision,
not a compatibility claim in this repository.
