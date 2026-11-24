# Using passkeys

A passkey signs you in with your fingerprint, face, screen lock or a security key instead of a
password. It works only on your organization's site, so a fake site can't trick you into giving it
away. Most phones and computers can use one ([check yours](https://passkeys.dev/device-support/)).

## Add a passkey

After you sign in, you may see **Sign in faster next time** or **Set up a passkey to continue**.
Click **Create a passkey** and follow your device's prompt.

To add one at any time:

1. Open **My Passkeys**: add `/passkeys` to your site's address, such as
   `https://erp.example.com/passkeys`.
2. Click **Add a passkey**.
3. If **Confirm it's you** appears and you already have a passkey, your device's passkey prompt
   opens with it: confirm there, or close it and click **Use your password instead** if offered.
   Otherwise enter your password.
4. Follow your device's prompt. You'll see **Passkey added.**

## Sign in

On the sign-in page, click **Sign in with a passkey** and follow your device's prompt. Some browsers
also offer your passkey when you click into the email or username box.

If your passkey is on your phone and you're on a computer, pick the phone option in the browser's
prompt and scan the QR code with your phone. The site may then offer **Add a passkey to this device**,
so next time you can skip the phone. In Chrome, the first prompt may list only this device's
passkeys; to use your phone or a security key, close it and click **Sign in with a passkey** again.

If your site asks for a passkey after your password, your device's prompt opens by itself. If it
doesn't, or you closed it, click **Use a passkey**.

## Add a second passkey

One passkey on one phone means a lost phone locks you out. Add another:

- **On another device:** sign in there, open **My Passkeys** and click **Add a passkey**.
- **On a security key:** click **Add a passkey** and pick the security key in your device's prompt.

A card marked **Synced** is saved in your Apple, Google or password-manager account and appears on
your other devices signed in to it. **This device only** means it stays on that one device.

With two passkeys you can also turn on **Passwordless login only**, which turns off password sign-in
for your account.

## Remove a passkey

On **My Passkeys**, find the passkey by its name and **Last used** date. Click its trash icon, then
**Remove passkey**. You may be asked to confirm it's you. Removing a passkey signs you out on your
other devices; the one you're using stays signed in.

## New or lost device

- **New device:** a synced passkey is already there once you sign in to the same Apple, Google or
  password-manager account. If not, sign in with your password or your phone's QR code, then add a
  passkey on the new device.
- **Lost device:** sign in with another passkey or your password, open **My Passkeys** and remove
  the lost device's passkey. That also signs the lost device out. If someone may be using it right
  now, tell your administrator too.
- **Can't sign in at all:** ask your administrator to let you back in.

Something went wrong? See [Troubleshooting](troubleshooting.md).
