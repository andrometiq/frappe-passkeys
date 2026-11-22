# Quickstart

From install to your first passkey sign-in. You need a Frappe v15 or v16 site on HTTPS, bench
access, and a System Manager login.

1. Install the app. Use the branch that matches your Frappe version: `version-15` or `version-16`.

   ```bash
   bench get-app --branch version-16 https://github.com/Andrometiq/frappe-passkeys
   bench --site <site> install-app passkeys
   ```

   Nothing changes for your users yet: passkeys start switched off.

2. Set your site's address. Passkeys are tied to the address your users open and stop working
   if it changes, so use the final one.

   ```bash
   bench --site <site> set-config host_name https://erp.example.com
   ```

   It can take a minute to apply.

3. Turn passkeys on. In Desk, search for **Passkey Settings**. On the **Login Modes** tab, tick
   **Login with Passkey** and save. If the save is refused, the message says what to fix.
   Passwords keep working.

   System Managers are now asked to add a passkey (they can put it off for 3 sign-ins); everyone
   else sees a reminder they can dismiss. Change this on the **Enrollment** tab.

4. Add your passkey. Reload the page. When **Set up a passkey to continue** appears, click
   **Create a passkey** and follow your browser's prompt. No prompt? Open `/passkeys` and click
   **Add a passkey**.

5. Sign in with it. Log out, then click **Sign in with a passkey** on the login page.

## Next

- [Before you go live](operations.md#before-you-enable-passkeys-on-a-production-site)
- [Every setting](configuration.md)
- [If someone is locked out](recovery.md)
