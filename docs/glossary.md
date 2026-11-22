# Glossary

General passkey terms are explained on [passkeys.dev](https://passkeys.dev/docs/reference/terms/).

### RP ID
Relying party ID: the domain your passkeys belong to, such as `erp.example.com`. If
**Passkey RP ID** is blank, it is the host in your site's `host_name`. A passkey made for one RP ID
never works under another, so changing it makes every existing passkey [stale](#stale-passkey).

### Origin
A full web address passkeys work from, such as `https://erp.example.com`. Your `host_name` counts
automatically; list others in **Passkey Origins**, each HTTPS and on the RP ID or a subdomain of it.

### Stale passkey
Made for a different RP ID, usually before a domain change. It can't sign in here but is kept, and
works again if the RP ID is changed back. **Remove stale passkeys** on the **Relying Party** tab
deletes them. A passkey that is neither stale nor disabled is *usable*.

### Required passkey
By default every System Manager must add a passkey, and **Require a passkey from** adds other
users. After signing in they see **Set up a passkey to continue** and can put it off for 3
sign-ins (**Grace sign-ins**). The docs call this *enforcement*.

### Nudge
The **Sign in faster next time** reminder for users who aren't required to add a passkey. They
can dismiss it or switch it off for themselves. By default it appears at most 3 times, 30 days
apart. Set **Everyone else** to **Off** to stop it.

### Re-authentication window
For 10 minutes (by default) after signing in with a password or passkey, or confirming it's them,
users can add or remove passkeys without seeing **Confirm it's you**. Also called the *sudo window*.

### Flagged passkey
Its signature counter went backwards, which can mean it was copied. By default it still signs in and
its owner gets an email. Turn on **Hard-fail on Sign Count Regression** to refuse such sign-ins.

### Passkey Only Login
A per-user switch that turns off password, email-link and social sign-in for one account. Users see
it on **My Passkeys** as **Passwordless login only** and need at least two passkeys to turn it on. A
System Manager can turn it off on the user's **WebAuthn User Handle**.

### Finish setting up this passkey
Shown when someone signs in without a password using a passkey added without a fingerprint, face,
PIN or screen-lock check. They enter their password once; after that the passkey works on its own.
