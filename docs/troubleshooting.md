# Troubleshooting

Find the message you see. Each one says what it means and what to do.

## Signing in

### No passkey was used — you can try again or sign in another way.

The passkey prompt closed without one: it was cancelled or timed out, or this device has no passkey
for this site.

Try again. Is your passkey on your phone? Pick the phone option in the prompt and scan the QR code.
In Chrome, the first try may show only the passkeys saved on this device; the next one has the phone
option. No passkey yet? Sign in with your password and [add one](using-passkeys.md#add-a-passkey).

### That passkey didn't work here — it may have been removed. Sign in another way.

The site doesn't know this passkey any more, usually because it was removed from **My Passkeys**.
Your device still offers it.

Sign in another way and add a new passkey. If your device keeps offering the old one, delete it there.

### This passkey was made for another address and doesn't work on this site.

The site's passkey address (its [RP ID](glossary.md#rp-id)) changed after you added this passkey.

Sign in with your password, open **My Passkeys** and click **Add a passkey for this site**.
Administrators: see [Changing the RP ID](operations.md#changing-the-rp-id-or-moving-domains); the old
passkeys work again if the RP ID is changed back.

### This device can't use passkeys yet — sign in with your password instead.

When adding a passkey it reads **This browser can't create passkeys.** The browser has no passkey
support ([check yours](https://passkeys.dev/device-support/)), or the site is open at an address
passkeys don't cover, such as an IP address.

Update the browser or use another device, and open the site at its usual address.

### Passkeys aren't available right now.

The sign-in page couldn't start a passkey sign-in.

Sign in with your password and tell your administrator. Administrators: look in **Error Log** for
titles starting `passkeys:`. `passkeys: request host not in configured origins` means the site was
opened at an address passkeys don't cover (see [Passkey Settings](#passkey-settings) below).

### Couldn't use a passkey — sign in another way.

The sign-in failed, and the page doesn't say why.

Try once more. If it keeps failing, sign in with your password, remove that passkey from
**My Passkeys** and add it again.

### Too many attempts. Wait a moment, then try again.

Also **Too many attempts. Try again later.** and **You've hit the rate limit. Please try again
shortly.** There were too many tries from your account or your network. People in one office often
share one internet address, and so share the sign-in limit.

Wait a few minutes and try again.

### Verifying took too long. Try again.

The site didn't answer within 30 seconds while it checked your passkey or password, so the page
stopped waiting. If the sign-in went through anyway, the page takes you in.

Try again. If it keeps happening, tell your administrator. Administrators: look for slow requests
to `verify_second_factor` or `complete_uv_setup` in the web server logs.

### Finish setting up this passkey

This passkey was added without a fingerprint, face, PIN or screen-lock check, so it can't sign in
on its own yet.

Enter your password once. After that the passkey works by itself.

### We've let your administrator know. Please contact them to finish signing in.

Your organization requires a passkey, your reminders are used up, and you chose **Contact
administrator**.

Click **Try passkey setup again** and use your phone (pick the phone option and scan the QR code),
or wait for your administrator. Administrators: on the user's **User** form, in the **Passkeys**
section, click **Reset grace logins** or **Exempt from passkey enforcement**
([details](recovery.md#the-enrollment-prompt-blocks-a-user)).

## Managing passkeys

### This device already has a passkey for this account.

Nothing is wrong: this device or password manager already holds one for you.

To add a second, use another device or a security key
([how](using-passkeys.md#add-a-second-passkey)).

### This is your only passkey and passwordless login is on for your account…

Removing it would lock you out.

Add another passkey first, or turn off **Passwordless login only**. If the message names
**Disable Username/Password Login** instead, password sign-in is off for the whole site: add another
passkey first.

## Passkey Settings

### The Passkeys app's files didn't load in this browser, so passkeys can't be turned on here (you can still turn them off)…

The browser didn't get the app's scripts. The tab may predate the install, or the server isn't
serving the app's files. Turning passkeys off still saves, so you can back out of a setup that
doesn't load.

Reload the page. If the message stays, run `bench build --app passkeys`, then `bench restart`. On
Frappe Cloud, deploy the bench again. Wait a minute, then reload.

### No Relying Party ID can be resolved…

Also **Cannot enable passkeys: no Relying Party ID resolves…** when you save, and **Passkeys are
off on this site: no RP ID resolves.** in Desk. The app can't tell which domain passkeys belong to.

Set the site's address, wait a minute, then save again:

```bash
bench --site <site> set-config host_name https://erp.example.com
```

Or enter **Passkey RP ID** on the **Relying Party** tab.

### This site's address … isn't covered by the RP ID …

Also **Passkeys are off on this site: its address … isn't covered by the RP ID …**, and **The
resolved RP ID / origins do not match this site's current host…** on Passkey Settings. The address
in use, often an IP address or a second domain, isn't on the passkey domain.

Open the site at its usual address. If the address is right, set `host_name` to it (then wait a
minute) or add it to **Passkey Origins**; it must be the RP ID or a subdomain of it. Changing the
RP ID makes existing passkeys [stale](glossary.md#stale-passkey).
