# Proposal 05: decide where passkey settings live in core

> Design sketch only. Placement is a core-maintainer decision; re-read the current System Settings
> layout and the singles it links out to before implementing.

## Goal

Pick the native home for passkey configuration so operators find it where they already manage
authentication. In the app, everything lives in a standalone `Passkey Settings` single because an
app cannot cleanly extend the core System Settings schema. Core has no such constraint, and the
login modes conceptually belong beside `disable_user_pass_login`, email-link login, and two-factor
authentication in the System Settings **Login** area.

## Proposed change

Core precedent supports either shape, so this is a choice, not a porting requirement:

- **Fold in**: add a passkey tab or section to System Settings (the pattern used for the built-in
  two-factor settings). Best discoverability; couples ~40 fields and their validators to the
  System Settings controller.
- **Linked single**: keep a dedicated single DocType and link it from the System Settings Login
  area (the pattern used for LDAP Settings and Social Login Key). Keeps the large relying-party,
  mobile-association, and enforcement surface out of an already long form.
- A hybrid is viable: the login-mode toggles fold into System Settings, and the relying-party,
  mobile, and enforcement detail stays on a linked single.

Whichever shape is chosen, keep one owner for the stored values — do not split the same setting
across two singles — and keep every validator from the app's `Passkey Settings` controller attached
to wherever the fields land.

## Checklist

- [ ] Confirm the current System Settings tab/section layout and its validator structure at the
      target ref.
- [ ] Choose fold-in, linked single, or hybrid with core maintainers.
- [ ] Preserve the app's validate chain (mode floor, RP/origin validation, enforcement warnings)
      and the two whitelisted reads wherever the fields move.
- [ ] Migrate stored app values to the chosen home in the handover migration, with one owner per
      value.
- [ ] Update the settings client script and posture surfaces to the new location.
- [ ] Test that a site upgraded from the app finds every value intact in the new home.

No current-core compatibility is claimed until these checks pass at a recorded commit.
