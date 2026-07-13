# Configuration — Passkey Settings

Everything is configured from the **Passkey Settings** single DocType
(Desk → Passkey Settings). This page documents every field, its default, and the
security consequence of changing it, then the way the settings interact with each
other and with core's Two Factor Authentication.

The fieldnames below are the stored fieldnames; they are the same names the
feature will use as System Settings fields once it merges into Frappe core.

## Login Modes

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Login with Passkey** (`login_with_passkey`) | Off | Master switch for passwordless first-factor login and all of its login-page UI. Turning it **on** puts the passkey button and conditional-UI autofill on the login page and activates `begin_login` / `verify_login`. Turning it **off** removes the UI and refuses those ceremonies (existing credential rows are kept). It cannot be turned off if that would leave no passkey-capable mode enabled while any user is *Passkey Only Login* (see the matrix below). |
| **Passkey as Second Factor** (`passkey_as_second_factor`) | Off | Adds a passkey step-up after a correct password. **Requires core Two Factor Authentication to stay on** — enabling this is refused if System Settings → *Enable Two Factor Authentication* is off (see "Two-factor floor" below). Off by default. |
| **Allow OTP Fallback for Passkey Second Factor** (`passkey_2fa_allow_otp_fallback`) | On | When on, a user doing the passkey second factor can choose "use a one-time code instead" and complete with core's OTP. Turning it **off** removes the downgrade path for passkey holders — a lost authenticator then needs admin recovery. This is enforced server-side, not just in the UI: `fallback_to_otp` re-checks the live setting and refuses when off, so a tampered client cannot force the weaker path. |

## Relying Party

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Passkey RP ID** (`passkey_rp_id`) | *blank ⇒ resolved from `host_name`* | The bare host a passkey is bound to (no scheme, port, or path). Blank means "use the exact host of the site's `host_name`". **This is a one-way door.** Changing it after any passkey is enrolled **invalidates every enrolled passkey** — all users must re-enroll. Widen to a parent domain only as a deliberate action; the Desk shows a typed confirm dialog restating the consequence. |
| **Passkey Origins** (`passkey_origins`) | *blank ⇒ `https://<rp_id>`* | The exact-match origin allowlist, one per line, explicit ports allowed. Each entry's host must equal the RP ID or be a subdomain of it, and must be HTTPS (`http://localhost` is allowed only under `developer_mode`). An out-of-scope or non-HTTPS entry is refused at save time, because such an origin would pass every server check and then fail permanently in the browser. |

The read-only **Resolved Configuration** panel shows the RP ID and origins the
server actually resolved, plus the invalidation warning and — if the current
request host does not match — a red mismatch banner.

## Mobile Apps

If a native iOS / Android app should share the site's passkeys, the **Mobile
Apps** fields configure the trusted native origins and the two well-known
association files: `passkey_app_origins`, `passkey_android_package_name`,
`passkey_android_cert_fingerprints`, `passkey_ios_team_id`, and
`passkey_ios_bundle_id`. They are documented in full — including how to obtain the
Android signing-certificate fingerprint and how the association files are served —
in [`mobile-apps.md`](mobile-apps.md). Leave them blank for a web-only site.

## Policy

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Hard-fail on Sign Count Regression** (`passkey_sign_count_hard_fail`) | Off | Controls what happens when an authenticator presents a signature counter *lower* than the stored value (a possible clone signal). Off (default): the sign-in proceeds but the credential is flagged and its owner is emailed. On: such an assertion is rejected. A counter that is *equal and non-zero* (a replay) is always rejected regardless of this knob. |
| **Maximum Passkeys per User** (`passkey_max_per_user`) | 10 | Per-user credential cap; registration is refused once a user reaches it. Lowering it does not delete existing rows. |
| **Re-authentication Window (Seconds)** (`passkey_reauth_window`) | 600 | Lifetime of the "sudo" window — how long after a fresh login (or a password / passkey re-auth) the management surface lets a user add or delete passkeys without confirming again. Longer is more convenient and less strict; shorter re-prompts sooner. Does not affect action-confirmation grants, which are always single-use and short-lived. |
| **Allow First Enrollment on Weak Login** (`passkey_allow_first_enrollment_on_weak_login`) | On | Lets a user who signed in with a "weak" method (email link or social/OAuth) enroll their **first** passkey, within a short window after that login. Off: social-only accounts with no password can never enroll a passkey. It only ever authorizes a *first* credential; subsequent adds always need a full sudo window. |

## Enrollment

The **Enrollment Policy** is the rung control of the passkey adoption ladder — it
decides whether, and how hard, the app pushes passkey-less users to enroll. The
nudge and conditional-create knobs tune the softer rungs; the separate
**Enforcement Scope & Escape Hatches** section below only takes effect on the
harder ones.

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Enrollment Policy** (`passkey_enrollment_policy`) | Nudge | The adoption-ladder rung, a Select of four values. **Off** — never prompt. **Nudge** — show a dismissible "set up a passkey" prompt after login to users who have none, capped by the two nudge knobs below. **Enforce** — in-scope users must register a passkey to keep using the app (recovery stays available). **Enforce After Date** — behaves as *Nudge* until the date in *Enforce After*, then becomes *Enforce*. Enforce is a **post-login interstitial**: the session already exists before it runs, so it raises friction toward enrollment but is not a server-side authentication block. |
| **Enforce After** (`passkey_enforce_after`) | *blank* | Only shown, and required, when the policy is *Enforce After Date*. Enforcement begins on this date, evaluated against the server clock on every request; before it the policy behaves as *Nudge*, and a past date behaves as an immediate *Enforce*. |
| **Maximum Nudge Prompts** (`passkey_nudge_max_prompts`) | 3 | How many times a user is nudged before the app stops (applies to *Nudge*, and to *Enforce After Date* while it is still before its date). Counters are server-side per user (a three-browser user gets 3 prompts total, not 9). |
| **Nudge Cooldown (Days)** (`passkey_nudge_cooldown_days`) | 30 | Minimum days between nudges to the same user. |
| **Conditional Create** (`passkey_conditional_create`) | On | Lets the browser silently create a passkey after a password login when the platform supports it (no dialog). The server only allows this off a **password**-seeded fresh-login window. Off: only the explicit nudge/enroll flow creates passkeys. |

## Enforcement Scope & Escape Hatches

This section is shown, and takes effect, **only** when **Enrollment Policy** is
*Enforce* or *Enforce After Date*. It scopes who enforcement applies to and keeps
capable-but-stuck users — and administrators — from being dead-ended.

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Enforcement Scope** (`passkey_enforce_scope`) | All Users | Whether enforcement applies to everyone (*All Users*) or only to users holding one of the selected roles (*Selected Roles*). |
| **Enforce for Roles** (`passkey_enforce_roles`) | *empty* | Only shown when scope is *Selected Roles*. A user is in scope for enforcement if they hold **any** of these roles. |
| **Exempt Roles** (`passkey_enforce_exempt_roles`) | System Manager *(seeded)* | Users holding **any** of these roles are always exempt — the break-glass hatch. `System Manager` is seeded automatically (on install and on upgrade) so an administrator can never lock themselves out the moment enforcement is turned on. |
| **Grace Logins** (`passkey_enforce_grace_logins`) | 3 | How many more sign-ins an in-scope user may defer the enrollment prompt before it becomes blocking. Covers a brand-new user's first session; `0` blocks immediately. |
| **Incapable Device Policy** (`passkey_enforce_incapable`) | Degrade to Nudge | What to do when a device genuinely cannot create a passkey (no platform authenticator and no cross-device option). *Degrade to Nudge* never locks the device out; *Block + Notify Admin* keeps prompting and records a risk event instead. |
| **Allow Hybrid (Phone / QR) Enrollment** (`passkey_enforce_allow_hybrid`) | On | On a device with no platform authenticator, offer enrollment via a phone / QR code (cross-device) so users who are capable via a phone are not dead-ended. |

### A user can't get past enforcement — what to do

Enforce is a **post-login interstitial**, not an auth block, so a stuck user is
never truly locked out — the levers below go from least to most drastic. Pick the
narrowest one that fits.

1. **They said "I can't set one up here."** With the default *Incapable Device
   Policy* (**Degrade to Nudge**) the interstitial already let them through as a
   dismissible nudge, and their administrators were emailed. Nothing is blocking;
   help them enroll on a capable device (or issue a security key) when convenient.
   Only **Block + Notify Admin** keeps the gate up — the fixes below apply then.
2. **Exempt this one user (one click).** Open the user's **User** form → the
   **Passkeys** section (System Managers see it on anyone's form). While the policy
   is *Enforce* / *Enforce After Date* it shows two admin actions; click **Exempt
   from passkey enforcement**. Under the hood this assigns the dedicated
   **`Passkey Enforcement Exempt`** role (created on first use) and adds it to
   *Exempt Roles* — the user drops out of scope immediately. **Remove enforcement
   exemption** reverses it. The role and the *Exempt Roles* entry are left in place
   for reuse.
3. **Give them more grace logins.** In the same section, **Reset grace logins**
   restores the user's full deferral budget (the *Grace Logins* count) so the
   interstitial goes back to "Remind me later" instead of blocking. Use it to buy a
   capable-but-not-right-now user time to enroll.
4. **Adjust scope or roles.** If a whole group is caught wrongly, narrow
   **Enforcement Scope** to *Selected Roles* (and set *Enforce for Roles*), or add a
   role they all share to **Exempt Roles**. Both take effect on the next login.
5. **Back off the policy.** Flipping **Enrollment Policy** to **Nudge** turns every
   interstitial back into a dismissible prompt site-wide — the escape hatch when a
   rollout is biting more users than expected.

**Break-glass guarantee:** **System Manager** is a seeded *Exempt Role*, so an
administrator is never enforced and can always reach these settings — even if the
policy is misconfigured. Keep it exempt unless you are certain.

## Notifications

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Notify on Passkey Changes** (`passkey_notify_on_change`) | On | Sends the account owner an email (with label, time, and IP) whenever a passkey is added, removed, disabled, or flagged. This email is the **compensating control for registration hijack** — a user who did not initiate the change can react. Turning it off is warned against; only do so on mail-less development sites. Activity Log rows are written either way. |
| **Notify on Password Fallback** (`passkey_notify_password_fallback`) | Off | When on, emails a passkey holder if a sign-in used a one-time code instead of their passkey. Opt-in telemetry; off by default. |
| **Notify on Password Login by Passkey Holder** (`passkey_notify_password_login`) | Off | When on, records an Activity Log risk event whenever a user who holds at least one enabled passkey signs in with their password instead. This is telemetry, not an email — it surfaces accounts still leaning on the password so an operator can drive enrollment. Opt-in and off by default *specifically* so the "does this user have a passkey?" lookup never touches the hot login path on a default site; a site that wants the signal turns it on. |

## The two-factor floor (both directions)

"Passkey as Second Factor" is enforced structurally, by keeping core's Two Factor
Authentication turned on. The app guards this pairing from **both** sides:

- **Enabling passkey 2FA** requires System Settings → *Enable Two Factor
  Authentication* to already be on. Saving Passkey Settings with
  `passkey_as_second_factor` on while core 2FA is off is refused. The reason:
  users who post their credentials directly (bypassing the passkey UI) must still
  meet a second factor — core's own OTP is that backstop on every branch.
  If core 2FA is on but *no role* has two-factor enabled, the save proceeds with
  an orange warning (the backstop then covers nobody — enable it for role `All`).

- **Disabling core Two Factor Authentication** is refused while
  `passkey_as_second_factor` is on. Attempting to turn *Enable Two Factor
  Authentication* from on to off in System Settings throws, because it would
  silently evaporate the backstop while the passkey-2FA UI kept working. Turn off
  "Passkey as Second Factor" in Passkey Settings first.

A raw `bench console` / `db_set` edit can bypass both validators and leave the
two desynced (`passkey_as_second_factor=1` while core 2FA is off). The first-leg
endpoint detects this at runtime and writes a once-daily error-log entry naming
the fix; see [`operations.md`](operations.md).

## Settings interaction matrix (operator terms)

| Situation | What happens |
|---|---|
| Both login modes off (freshly installed) | Legal "paused" state. Login and second-factor ceremonies refuse, all UI removes itself, credential rows are preserved, and the action-confirmation primitive still works. |
| Only "Passkey as Second Factor" on ("2FA-only" site) | Legal. The passwordless login button does not appear, but registration and management stay available so users can enroll, and the second-factor endpoints are live. |
| Enable passkey 2FA while core 2FA is off | Refused at save. Turn on Two Factor Authentication first. |
| Turn core Two Factor Authentication off while passkey 2FA is on | Refused at save. Turn off "Passkey as Second Factor" first. |
| Turn off the last passkey-capable mode while a Passkey-Only user exists | Refused at save, with the flagged users listed. Keep a passkey login mode on, or clear "Passkey Only Login" on those users first. This holds whether the last mode is "Login with Passkey" or "Passkey as Second Factor". |
| A Passkey-Only user does the password→passkey second-factor flow | Allowed — that path is a passkey login, so it satisfies the account's passkey-only rule. |
| A Passkey-Only user with Login With Email Link on | The email-link path is closed for that user; only their passkey gets them in. |
| OTP fallback off and a passkey holder loses their authenticator | No self-service downgrade — admin recovery only (see [`recovery.md`](recovery.md)). |
| "Passkey as Second Factor" on together with "Disable Username/Password Login" (core) | A dead combination — the password leg has nothing to run against. The save proceeds with an orange warning (LDAP/social may still feed core 2FA). |
| Change notifications off while a login mode is on | The save proceeds with an orange warning: this weakens the main defence against registration hijack. |

## Per-user "Passkey Only Login"

This is a **per-user** switch (on the user's WebAuthn User Handle row), not a
site setting. It disables password / email-link / social first-factor login for
that one user — they must sign in with a passkey. It is the released-branch lever
for "no passwords for this account"; the site-wide equivalent needs the
self-hoster override in [`operations.md`](operations.md).

- Only the user themself can turn it on or off, and only by presenting a fresh
  **passkey** confirmation — never a password and never a sudo window. (A password
  must not be able to switch off the very flag that says "a password is not
  enough".)
- Enabling it requires **at least two enabled passkeys**, so a single lost device
  never locks the account out.
- **Administrator is exempt** from this restriction, mirroring core's 2FA
  exemption — the site owner can always get in with a password. This is the
  standing recovery invariant; see [`security.md`](security.md) and
  [`recovery.md`](recovery.md).
