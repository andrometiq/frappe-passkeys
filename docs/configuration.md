# Configuration — Passkey Settings

Everything is configured from the **Passkey Settings** single DocType
(Desk → Passkey Settings). This page documents every field, its default, and the
security consequence of changing it, then the way the settings interact with each
other and with core's Two Factor Authentication.

The fieldnames below are the app's stored fieldnames. The upstream documents propose
reusing them in System Settings, but no current-core compatibility or merge is assumed.

## Login Modes

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Login with Passkey** (`login_with_passkey`) | Off | Master switch for passwordless first-factor login and all of its login-page UI. Turning it **on** puts the passkey button and conditional-UI autofill on the login page and activates `begin_login` / `verify_login`. Turning it **off** removes the UI and refuses those ceremonies (existing credential rows are kept). It cannot be turned off if that would leave no passkey-capable mode enabled while any user is *Passkey Only Login* (see the matrix below). |
| **Passkey as Second Factor** (`passkey_as_second_factor`) | Off | Adds a passkey step-up after a correct password. **Requires core Two Factor Authentication to stay on** — enabling this is refused if System Settings → *Enable Two Factor Authentication* is off (see "Two-factor floor" below). Off by default. |
| **Allow OTP Fallback for Passkey Second Factor** (`passkey_2fa_allow_otp_fallback`) | On | When on, a user doing the passkey second factor can choose "use a one-time code instead" and complete with core's OTP. Turning it **off** removes the downgrade path for passkey holders — a lost authenticator then needs admin recovery. This is enforced server-side, not just in the UI: `fallback_to_otp` re-checks the live setting, and final session minting re-checks that core 2FA still covers the user before consuming the one-time marker. |

## Relying Party

Enabling either authentication mode also requires the site's `encryption_key`. The save is refused
when it is absent: second-factor ceremonies bind password-hash versions with that key, and lifecycle
exports use it for integrity. Back the key up separately before enrolling production users.

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Passkey RP ID** (`passkey_rp_id`) | *blank ⇒ resolved from `host_name`* | The bare host a passkey is bound to (no scheme, port, or path). Blank means "use the exact host of the site's `host_name`". **This is a one-way door.** Changing it after any passkey is enrolled **invalidates every enrolled passkey** — all users must re-enroll. Widen to a parent domain only as a deliberate action; the Desk shows a typed confirm dialog restating the consequence. |
| **Passkey Origins** (`passkey_origins`) | *blank ⇒ no additional origins* | Exact web origins, one per line; explicit ports are allowed. The exact origin from `host_name` is included automatically only when its host equals the RP ID or is a subdomain of it. The RP ID never implies trust in `https://<rp_id>`. Enabling a login mode is refused when the resolved web-origin set is empty. Each origin must be HTTPS (`http://localhost` is allowed only under `developer_mode`) and within RP-ID scope. |

For example, `host_name = https://login.example.com` and RP ID `example.com` trusts
`https://login.example.com`; it does **not** also trust `https://example.com`. Add the apex origin
explicitly only if the site or an iOS app genuinely uses it. The read-only **Resolved
Configuration** panel shows the exact server-resolved set, plus the invalidation warning and a
host-mismatch banner when the current request host is outside that set.

## Mobile Apps

If a native iOS / Android app should share the site's passkeys, the **Mobile
Apps** fields configure the trusted native origins and the two well-known
association files: `passkey_app_origins`, `passkey_android_package_name`,
`passkey_android_cert_fingerprints`, `passkey_ios_team_id`, and
`passkey_ios_bundle_id`. They are documented in full — including how to obtain the
Android signing-certificate fingerprint and how the association files are served —
in [`mobile-apps.md`](mobile-apps.md). Leave them blank for a web-only site.

## Enrollment

**Require a passkey from** decides who must enroll after they sign in. That prompt is a
post-login interstitial: the session already exists, so it raises friction toward enrollment
and is never a server-side login block. Phone / QR enrollment is always offered; a device
counts as capable when it has a platform authenticator or a cross-device option. Users
outside the scope take **Everyone else**. A blank **Starting on** means immediately; until
that date, in-scope users are nudged instead of required. The exempt marker role beats
every scope rule, including System Managers.

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Require a passkey from** (`passkey_enforce_scope`) | No one | *No one*, *Selected roles*, or *All users*. In-scope users must enroll after signing in, after grace sign-ins. |
| **Roles** (`passkey_enforce_roles`) | *empty* | Shown when scope is *Selected roles*. A user is in scope if they hold **any** of these roles. |
| **Always require a passkey from System Managers** (`passkey_enforce_privileged_always`) | On | Adds System Managers (and Administrator) to the scope above, whatever it is. Hidden when scope is *All users*, because they are already included. Turning it off under *Selected roles* warns. A per-user exemption still wins. |
| **Starting on** (`passkey_enforce_after`) | *blank* | Blank means immediately. Until this date, in-scope users are nudged instead of required. A past date is immediate. Shown when scope is not *No one*, or System Managers are always included. |
| **Everyone else** (`passkey_everyone_else`) | Nudge | Users outside the scope: *Nudge* (a dismissible prompt, capped below) or *Off* (nothing). Hidden when scope is *All users*. The exempt marker takes this rung too. |
| **Grace sign-ins** (`passkey_enforce_grace_logins`) | 3 | How many more sign-ins an in-scope user may defer the enrollment prompt before it becomes blocking. A defer can consume at most one grace login per session, even if the endpoint is retried or multiple tabs render the prompt. `0` blocks immediately. Shown under **When a passkey is required**. |
| **Device cannot create a passkey** (`passkey_enforce_incapable`) | Degrade to Nudge | What to do when a device genuinely cannot create a passkey (no platform authenticator and no cross-device option). *Degrade to Nudge* uses the ordinary opt-out, prompt cap and cooldown on both Desk and portal, and never locks the device out; *Block + Notify Admin* keeps prompting and records a risk event instead. |
| **Maximum prompts per user** (`passkey_nudge_max_prompts`) | 3 | How many times the dismissible prompt may appear. Applies to *Everyone else* = Nudge, to in-scope users before **Starting on**, and to incapable devices under *Degrade to Nudge*. Counters are server-side per user (a three-browser user gets 3 prompts total, not 9). |
| **Days between prompts** (`passkey_nudge_cooldown_days`) | 30 | Minimum days between those prompts. |
| **Conditional Create** (`passkey_conditional_create`) | On | Lets the browser silently create a passkey after a password login when the platform supports it (no dialog). The server only allows this off a **password**-seeded fresh-login window. Off: only the explicit nudge/enroll flow creates passkeys. |

### A user can't get past enforcement — what to do

Enforce is a **post-login interstitial**, not a pre-session authentication block,
but **Block + Notify Admin** can still prevent useful application access. The
levers below go from least to most drastic. Pick the narrowest one that fits.

1. **They said "I can't set one up here."** With the default *Device cannot create a
   passkey* (**Degrade to Nudge**) the interstitial already let them through as a
   dismissible nudge (or silently when opted out, capped or cooling down), without emailing
   administrators. Nothing is blocking;
   help them enroll on a capable device (or issue a security key) when convenient.
   Only **Block + Notify Admin** keeps the gate up; there the button reads
   **Contact administrator**, because clicking it emails the System Managers. The
   fixes below apply then.
2. **Exempt this one user (one click).** Open the user's **User** form → the
   **Passkeys** section (System Managers see it on anyone's form). While a passkey
   is required from someone, it shows two admin actions; click **Exempt
   from passkey enforcement**. Under the hood this assigns the dedicated
   **`Passkey Enforcement Exempt`** marker role (created on first use) — the user
   takes the **Everyone else** rung immediately, including a `System Manager` covered by
   *Always require a passkey from System Managers*. **Remove enforcement exemption** reverses
   it. The marker role remains available for reuse, but only explicit per-user
   assignments exempt anyone; there is no role-wide exemption setting.
3. **Give them more grace logins.** In the same section, **Reset grace logins**
   restores the user's full deferral budget (the *Grace sign-ins* count) so the
   interstitial goes back to "Remind me later" instead of blocking. Use it to buy a
   capable-but-not-right-now user time to enroll.
4. **Adjust scope or roles.** If a whole non-privileged group is caught wrongly,
   set **Require a passkey from** to *Selected roles* and list **Roles**.
   This takes effect on the next login. System Managers stay in scope while
   *Always require a passkey from System Managers* is on.
5. **Back off the requirement.** Set **Require a passkey from** to **No one** and
   untick **Always require a passkey from System Managers**. In-scope interstitials
   stop; **Everyone else** still decides whether everyone else sees a nudge.
6. **If every administrator is locked out, use the server console.** Disable the
   enrollment gate without invoking the settings controller:

   ```bash
   bench --site <site> execute passkeys.recovery.disable_enforcement
   ```

   This idempotently sets **Require a passkey from** to *No one* and unticks
   **Always require a passkey from System Managers**. Every other Passkey Setting,
   including **Everyone else**, is left untouched. Frappe core also provides operator
   recovery hatches for restoring an administrator account:

   ```bash
   bench --site <site> add-system-manager <email>
   bench --site <site> set-admin-password <new-password>
   ```

There are no standing role-wide exemptions. Administrators are enforced first by
default; recovery is an explicit temporary marker-role assignment for one user or
an operator-only console action when no administrator can reach Desk.

Enforcement, Passkey Only Login and disabled password login govern interactive sign-in only;
API-key and OAuth-token requests are not subject to them (see
[API keys and OAuth tokens](security.md#api-keys-and-oauth-tokens)).

## Security

| Field | Default | What it does / consequence of changing it |
|---|---|---|
| **Hard-fail on Sign Count Regression** (`passkey_sign_count_hard_fail`) | Off | Controls what happens when an authenticator presents a signature counter *lower* than the stored value (a possible clone signal). Off (default): the sign-in proceeds but the credential is flagged and its owner is emailed. On: such an assertion is rejected. A counter that is *equal and non-zero* (a replay) is always rejected regardless of this knob. |
| **Maximum Passkeys per User** (`passkey_max_per_user`) | 10 | Per-user credential cap; registration is refused once a user reaches it. Lowering it does not delete existing rows. |
| **Re-authentication Window (Seconds)** (`passkey_reauth_window`) | 600 | Lifetime of the "sudo" window — how long after a fresh login (or a password / passkey re-auth) the management surface lets a user add or delete passkeys without confirming again. Longer is more convenient and less strict; shorter re-prompts sooner. Does not affect action-confirmation grants, which are always single-use and short-lived. |
| **Allow First Enrollment on Weak Login** (`passkey_allow_first_enrollment_on_weak_login`) | On | When **Login with Passkey** is also on, lets a user who signed in with a "weak" method (email link or social/OAuth) enroll their **first** passkey within a short window. It is refused on second-factor-only sites because the same weak login would be vetoed after enrollment while no passkey first-factor route exists. Off: social-only accounts with no password cannot bootstrap a passkey. Subsequent adds always need a full sudo window. |

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
  the app relies on core's 2FA machinery as a structural floor in addition to its
  own login veto.
  If core 2FA is on but *no role* has two-factor enabled, the save proceeds with
  an orange warning (the backstop then covers nobody — enable it for role `All`).

- **Disabling core Two Factor Authentication** is refused while
  `passkey_as_second_factor` is on. Attempting to turn *Enable Two Factor
  Authentication* from on to off in System Settings throws, because it would
  silently evaporate the backstop while the passkey-2FA UI kept working. Turn off
  "Passkey as Second Factor" in Passkey Settings first.

A raw `bench console` / `db_set` edit can bypass both validators and leave the
two desynced (`passkey_as_second_factor=1` while core 2FA is off). The final login
veto still blocks enrolled users, and the security posture panel on the Passkey
Settings page flags the missing floor.

For a user with an enabled passkey, the second-factor requirement is enforced at the final login
hook, not only by the app's login-page JavaScript. Password, email-link, social/OAuth, LDAP, and
other core login paths are vetoed unless this app completed the passkey step or explicitly handed
the user to core OTP via `fallback_to_otp`. That OTP handoff creates a short-lived, one-time marker
bound to core's `tmp_id`; a direct call to core OTP without that marker remains blocked. The rule
also applies to **Administrator after Administrator has explicitly enrolled an enabled passkey**.

Every password-to-passkey ceremony captures a keyed, non-reversible version of the current password
hash at the password leg and compares it again immediately before session minting. A password
rotation during the ceremony therefore fails closed without retaining the password for the normal
passkey-only leg. The password itself is retained only where an allowed OTP fallback, or an external
authentication account without a local hash marker, requires core to re-authenticate.

## Settings interaction matrix (operator terms)

| Situation | What happens |
|---|---|
| Both login modes off (freshly installed) | Legal "paused" state. Login and second-factor ceremonies refuse, all UI removes itself, credential rows are preserved, and the action-confirmation primitive still works. |
| Only "Passkey as Second Factor" on ("2FA-only" site) | Legal for users who can start the app's local password flow. The passwordless login button does not appear. An enrolled social-, LDAP-, or email-link-only account cannot complete those alternate paths because the final veto requires this app's passkey/OTP handoff; keep "Login with Passkey" on for such accounts. |
| Enable passkey 2FA while core 2FA is off | Refused at save. Turn on Two Factor Authentication first. |
| Turn core Two Factor Authentication off while passkey 2FA is on | Refused at save. Turn off "Passkey as Second Factor" first. |
| Turn off the last passkey-capable mode while a Passkey-Only user exists | Refused at save, with the flagged users listed. Keep a passkey login mode on, or clear "Passkey Only Login" on those users first. This holds whether the last mode is "Login with Passkey" or "Passkey as Second Factor". |
| A Passkey-Only user does the password→passkey second-factor flow | Allowed — that path is a passkey login, so it satisfies the account's passkey-only rule. |
| An enrolled second-factor user uses password, email link, social/OAuth, LDAP, or another core login path | The final login is vetoed unless this app completed passkey verification or issued and then consumed the one-time OTP fallback marker. This includes an enrolled Administrator. |
| A Passkey-Only user with Login With Email Link on | The email-link path is closed for that user; only their passkey gets them in. |
| OTP fallback off and a passkey holder loses their authenticator | No self-service downgrade — admin recovery only (see [`recovery.md`](recovery.md)). |
| "Passkey as Second Factor" on together with "Disable Username/Password Login" (core) | A dead combination for enrolled users — the app's password leg has nothing to run against, and alternate login completions are final-vetoed. Refused at save, from either settings page, while "Passkey as Second Factor" is the only passkey mode. With "Login with Passkey" also on, the save proceeds with an orange warning. |
| Change notifications off while a login mode is on | The save proceeds with an orange warning: this weakens the main defence against registration hijack. |

## Per-user "Passkey Only Login"

This is a **per-user** switch (on the user's WebAuthn User Handle row), not a
site setting. It disables password / email-link / social first-factor login for
that one user — they must sign in with a passkey. An existing password hash is kept, just
unusable for sign-in while the switch is on. It is the released-branch lever
for "no passwords for this account"; the site-wide equivalent needs the
self-hoster override in [`operations.md`](operations.md).

- Only the user themself can turn it on or off, and only by presenting a fresh
  **passkey** confirmation — never a password and never a sudo window. (A password
  must not be able to switch off the very flag that says "a password is not
  enough".)
- Enabling it requires **at least two enabled passkeys**, so a single lost device
  never locks the account out.
- **Administrator is exempt only from this per-user passkey-only login veto.** That preserves the
  password break-glass path for an Administrator who has not opted into the passkey second factor.
  Once Administrator explicitly enrolls an enabled credential while *Passkey as Second Factor* is
  active, alternate/core login paths are protected exactly like any other enrolled user's. The
  site-wide `disable_user_pass_login` flag also has no Administrator exemption. See
  [`security.md`](security.md) and [`recovery.md`](recovery.md).

## Transactional race protection

Security-sensitive read/modify/write paths take database locks in a consistent order. Credential
assertion bookkeeping re-locks the credential before advancing counters; UV setup locks the user and
credential; registration locks the user, handle, and credential census before applying the per-user
cap and insert; passkey-only credential deletion/toggling locks the shared login floor; Passkey
Settings mode changes lock the Single rows before checking flagged users; and the Passkey Settings /
System Settings floor checks read each other's values with locking reads. These locks make concurrent
verification, registration, deletion, flag changes, and settings saves serialize instead of each
committing from a stale snapshot.
