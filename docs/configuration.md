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

## Policy

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Hard-fail on Sign Count Regression** (`passkey_sign_count_hard_fail`) | Off | Controls what happens when an authenticator presents a signature counter *lower* than the stored value (a possible clone signal). Off (default): the sign-in proceeds but the credential is flagged and its owner is emailed. On: such an assertion is rejected. A counter that is *equal and non-zero* (a replay) is always rejected regardless of this knob. |
| **Maximum Passkeys per User** (`passkey_max_per_user`) | 10 | Per-user credential cap; registration is refused once a user reaches it. Lowering it does not delete existing rows. |
| **Re-authentication Window (Seconds)** (`passkey_reauth_window`) | 600 | Lifetime of the "sudo" window — how long after a fresh login (or a password / passkey re-auth) the management surface lets a user add or delete passkeys without confirming again. Longer is more convenient and less strict; shorter re-prompts sooner. Does not affect action-confirmation grants, which are always single-use and short-lived. |
| **Allow First Enrollment on Weak Login** (`passkey_allow_first_enrollment_on_weak_login`) | On | Lets a user who signed in with a "weak" method (email link or social/OAuth) enroll their **first** passkey, within a short window after that login. Off: social-only accounts with no password can never enroll a passkey. It only ever authorizes a *first* credential; subsequent adds always need a full sudo window. |

## Enrollment

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Enrollment Nudge** (`passkey_enrollment_nudge`) | On | Shows a dismissible "set up a passkey" prompt after login to users who have none. Off: no nudges. |
| **Maximum Nudge Prompts** (`passkey_nudge_max_prompts`) | 3 | How many times a user is nudged before the app stops. Counters are server-side per user (a three-browser user gets 3 prompts total, not 9). |
| **Nudge Cooldown (Days)** (`passkey_nudge_cooldown_days`) | 30 | Minimum days between nudges to the same user. |
| **Conditional Create** (`passkey_conditional_create`) | On | Lets the browser silently create a passkey after a password login when the platform supports it (no dialog). The server only allows this off a **password**-seeded fresh-login window. Off: only the explicit nudge/enroll flow creates passkeys. |

## Notifications

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Notify on Passkey Changes** (`passkey_notify_on_change`) | On | Sends the account owner an email (with label, time, and IP) whenever a passkey is added, removed, disabled, or flagged. This email is the **compensating control for registration hijack** — a user who did not initiate the change can react. Turning it off is warned against; only do so on mail-less development sites. Activity Log rows are written either way. |
| **Notify on Password Fallback** (`passkey_notify_password_fallback`) | Off | When on, emails a passkey holder if a sign-in used a one-time code instead of their passkey. Opt-in telemetry; off by default. |

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
