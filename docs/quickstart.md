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

3. Turn passkeys on. Reload Desk, then search for **Passkey Settings**. On the **Login Modes**
   tab, tick **Login with Passkey**.

   Saving asks System Managers to add a passkey (they can put it off for 3 sign-ins). Everyone
   else gets a reminder they can dismiss; some browsers add a passkey for them on their own after
   a password sign-in. The **Enrollment** tab changes who is asked. Passwords keep working.

   Save. If the form says no Relying Party ID can be resolved, wait a minute for step 2 to take
   effect and save again.

4. Add your passkey. Reload the page. When **Set up a passkey to continue** appears, click
   **Create a passkey** (enter your password if asked) and follow your browser's prompt. Not
   asked to set one up? Open `/passkeys` and click **Add a passkey**.

5. Sign in with it. Log out, then click **Sign in with a passkey** on the login page.

## Next

- [Before you go live](operations.md#before-you-enable-passkeys-on-a-production-site)
- [Every setting](configuration.md)
- [If someone is locked out](recovery.md)
