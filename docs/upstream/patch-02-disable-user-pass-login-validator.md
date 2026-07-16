# Proposal 02: count native passkeys as a surviving login method

> Design sketch only. It must be rebased onto current System Settings validation and may land only
> with a native passkey field and runtime that have been implemented and tested.

## Goal

When site-wide username/password login is disabled, core should accept native passkey first-factor
login as a surviving method. It must still reject a configuration with no working login method.

## Proposed change

Extend the current surviving-method predicate to include the final native passkey-login setting. Do
not reference a field before its DocType schema exists, and do not infer runtime readiness from a
truthy database value alone.

## Checklist

- [ ] Identify the current validator and every login path affected by `disable_user_pass_login`.
- [ ] Add the native field and validator in the same reviewed change or sequence that guarantees
      schema availability.
- [ ] Verify passkey login actually survives the core password-disable gate at the target ref.
- [ ] Preserve Administrator behavior: site-wide password disable has no implicit break-glass
      exemption, so recovery requires a tested passkey or console path.
- [ ] Keep per-user credential floors and passkey-mode settings locks; this site-wide predicate is
      not a replacement for them.
- [ ] Test each surviving method alone, combinations, all methods off, migration, and rollback.

No current-core compatibility is claimed until these checks pass at a recorded commit.
