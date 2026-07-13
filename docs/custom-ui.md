# Build your own passkey UI

This app ships a complete, ready-to-use passkey experience — a login-page button,
a `/passkeys` self-service page, and a "Passkeys" section on the User form. You do
**not** need any of this to build your own.

Three integration levels, from least to most work:

| You want to… | Use | Guide |
| --- | --- | --- |
| Ship fast, restyle the app's barebones cards | The shipped cards + your CSS | [Semantic markup contract](#semantic-markup-contract) below |
| Build your own markup but reuse the ceremony logic | The **headless JS API** (`frappe.passkeys.headless`) | This page |
| Integrate with no JS asset at all (mobile, SPA) | The **REST endpoints** directly | [`rest-api.md`](rest-api.md) |

The headless API is the same code the app's own portal card engine calls, so your
custom UI runs the exact, tested ceremony path the shipped UI does. It carries **no
markup and no styling** — you supply the DOM, it does the WebAuthn + server dance.

---

## The public JavaScript surface

Everything below is published on the `frappe` global. The lifecycle API lives under
`frappe.passkeys.headless`; the two pure libraries under `frappe.passkeys_*` are the
building blocks it (and you, if you go lower-level) are built on.

| Global | What it is |
| --- | --- |
| `frappe.passkeys.headless` | The markup-free lifecycle API (below). |
| `frappe.passkeys.confirm(action, params)` | Re-auth ("passkey signing") — resolve a single-use grant for a sensitive action. |
| `frappe.passkeys.call(method, args)` | Call a `@passkey_protected` method, running the confirmation on demand. |
| `frappe.passkeys.manage` | The **Desk-only** card renderers (`renderCards`, `openManagerDialog`, `addPasskey`, …). Not needed for a custom UI. |
| `frappe.passkeys_common` | Pure helpers: `detectCapabilities`, base64url, the L3 JSON shim, `mapDomException`, `LOGIN_STATES`, `createConfirmEngine`, … |
| `frappe.passkeys_manage_common` | Pure helpers: `MANAGE_METHODS`, `credentialViewModel`, `providerFor`, the nudge/enforcement decisions. |

`frappe.ui.passkey.headless` / `.confirm` / `.call` are forward-compatible aliases
(the intended core namespace).

### `frappe.passkeys.headless`

| Method | Resolves | Notes |
| --- | --- | --- |
| `detectCapabilities()` | `{supported, conditionalMediation, uvpaa, hybrid}` | `null` fields mean *unknown* — never coerce to `false`. |
| `login(opts?)` | a structured result (below) | First-factor discoverable sign-in: begin → `get()` → verify. `opts.mediation` / `opts.signal` for autofill. |
| `beginLogin()` | `{enabled, modes, stateId, options}` | Lower-level: fetch fresh options (also the config channel). |
| `verifyLogin(stateId, assertion)` | a structured result (below) | Lower-level: verify an assertion you ran yourself. |
| `register(opts?)` | `{name, label, signal}` | Add a passkey: begin (+ re-auth if needed) → `create()` → verify. `opts.label`, `opts.flow`. |
| `listCredentials()` | `{credentials, passkey_only_login}` | The caller's own passkeys. Not sudo-gated. |
| `renameCredential(name, label)` | `{name, label}` | Display-only, no re-auth. |
| `removeCredential(name)` | `{deleted}` | **Sudo-gated** — runs the confirmation engine. |
| `setPasswordlessOnly(enabled)` | `{passkey_only_login}` | Turn password login off/on for the account. Passkey re-auth only. |
| `confirm(action, params)` / `call(method, args)` | grant / result | Proxies to `frappe.passkeys.confirm` / `.call`. |

**Login result shape** — `login()` and `verifyLogin()` never throw on a server
refusal; they resolve one of:

```js
{ ok: true,  redirect }                                   // signed in — navigate to redirect (or reload)
{ ok: false, reason: "disabled" }                         // no first-factor mode / unconfigured
{ ok: false, reason: "gesture", code, message, statusState }   // the browser get() failed/was cancelled
{ ok: false, reason: "server", kind, message, setupId?, statusState } // typed server refusal
{ ok: false, reason: "network" }                          // transport failure
```

`code` is the fixed DOMException taxonomy (`user_cancelled`, `not_supported`, …),
`kind` the typed-error taxonomy (`ceremony_expired`, `unknown_credential`,
`uv_setup_required`, …). `statusState` maps to the shipped `LOGIN_STATES` copy if you
want to reuse it. **All failure copy is deliberately generic** — the server never
reveals whether an account or credential exists, and neither should your UI.

**Registration / management errors** — `register`, `renameCredential`,
`removeCredential` **reject** an `Error` whose `.code` is one of
`already_registered`, `user_cancelled`, `add_expired`, `add_failed`,
`not_supported`, `confirmation_unavailable`, `list_failed`, `rename_failed`. `.message`
is a human-readable string (the server's own message when it sent one — e.g. the
last-passkey delete guard — surfaced verbatim).

### Loading the assets

Serve these from the app's public tree (order matters — each reads the one before):

```html
<script src="/assets/passkeys/js/passkey_common.bundle.js"></script>          <!-- always -->
<script src="/assets/passkeys/js/passkey_manage_common.bundle.js"></script>   <!-- for management -->
<script src="/assets/passkeys/js/passkey_headless.bundle.js"></script>        <!-- the API -->
```

Every library ships as a `*.bundle.js` file. Esbuild content-hashes each one at
`bench build`, so on a **Frappe-rendered** page you should register the **bare bundle
name** (no `/assets` prefix) — via `web_include_js` on a website page, or `app_include_js`
in your `hooks.py` on Desk — and Frappe's `bundled_asset()` rewrites it to the hashed,
cache-busted URL. The raw `/assets/passkeys/js/…bundle.js` paths above are the
un-hashed physical fallback for a hand-rolled page Frappe doesn't render; they load, but
the browser may cache them across a deploy, so prefer the bare-name registration when you can.

A **login-only** page needs just `passkey_common.bundle.js` + `passkey_headless.bundle.js`. On Desk
and on the app's own portal pages these are already loaded for you, so
`frappe.passkeys.headless` is simply there.

---

## Example: a custom login page

Your own markup, your own styles. The only app dependency is the two scripts.

```html
<form id="signin">
  <label>Email <input id="email" autocomplete="username webauthn"></label>
  <label>Password <input id="password" type="password" autocomplete="current-password"></label>
  <button id="pw-signin">Sign in</button>
  <button type="button" id="passkey-signin">Sign in with a passkey</button>
  <p id="status" role="status" aria-live="polite"></p>
</form>

<script src="/assets/passkeys/js/passkey_common.bundle.js"></script>
<script src="/assets/passkeys/js/passkey_headless.bundle.js"></script>
<script>
  const pk = frappe.passkeys.headless;
  const status = document.getElementById("status");

  document.getElementById("passkey-signin").addEventListener("click", async () => {
    const caps = await pk.detectCapabilities();
    if (!caps.supported) { status.textContent = "This device can't use passkeys."; return; }

    status.textContent = "Waiting for your device…";
    const r = await pk.login();                 // begin → navigator.credentials.get() → verify
    if (r.ok) { window.location.assign(r.redirect || "/app"); return; }

    // One generic message per outcome — never leak whether an account exists.
    status.textContent =
      r.reason === "disabled"                  ? "Passkeys aren't available here." :
      r.reason === "network"                   ? "Couldn't reach the server — try again." :
      r.code === "not_supported"               ? "This device can't use passkeys." :
      r.kind === "unknown_credential"          ? "That passkey isn't recognised here — sign in another way." :
      /* cancelled / timed out / anything else */ "Couldn't sign in with a passkey — try another way.";
  });
</script>
```

**Autofill (conditional UI)** is opt-in. Give the username field
`autocomplete="username webauthn"` (above) and, on page load, run a *silent*
conditional ceremony you can cancel when the user starts typing a password:

```js
const ac = new AbortController();
pk.login({ mediation: "conditional", signal: ac.signal }).then((r) => {
  if (r.ok) window.location.assign(r.redirect || "/app");
});
// call ac.abort() before starting any explicit passkey/password flow
```

---

## Example: a custom "manage passkeys" page

```html
<ul id="cards"></ul>
<button id="add">Add a passkey</button>
<label><input type="checkbox" id="passwordless"> Passwordless login only</label>
<p id="msg" role="status" aria-live="polite"></p>

<script src="/assets/passkeys/js/passkey_common.bundle.js"></script>
<script src="/assets/passkeys/js/passkey_manage_common.bundle.js"></script>
<script src="/assets/passkeys/js/passkey_headless.bundle.js"></script>
<script>
  const pk = frappe.passkeys.headless;
  const M  = frappe.passkeys_manage_common;   // optional: card view-models + copy
  const cards = document.getElementById("cards");
  const msg = document.getElementById("msg");

  async function render() {
    const { credentials, passkey_only_login } = await pk.listCredentials();
    document.getElementById("passwordless").checked = !!passkey_only_login;
    cards.innerHTML = "";
    for (const cred of credentials) {
      const vm = M.credentialViewModel(cred);          // label, provider, Synced/Device-bound, dates
      const li = document.createElement("li");
      li.textContent = vm.label + (vm.badge.synced ? " · Synced" : " · Device-bound");
      // …your own Rename / Remove buttons, wired to the calls below…
      cards.appendChild(li);
    }
  }

  document.getElementById("add").addEventListener("click", async () => {
    try { await pk.register(); msg.textContent = "Passkey added."; render(); }
    catch (e) {
      if (e.code === "user_cancelled") return;
      msg.textContent = e.code === "already_registered"
        ? "This device already has a passkey for this account." : e.message;
    }
  });

  async function rename(name, label) { await pk.renameCredential(name, label); render(); }

  async function remove(name) {
    try { await pk.removeCredential(name); msg.textContent = "Passkey removed."; render(); }
    catch (e) { if (e.code !== "user_cancelled") msg.textContent = e.message; } // e.g. the last-passkey guard
  }

  document.getElementById("passwordless").addEventListener("change", async (ev) => {
    try { await pk.setPasswordlessOnly(ev.target.checked); render(); }
    catch (e) { ev.target.checked = !ev.target.checked; msg.textContent = e.message; }
  });

  render();
</script>
```

### Removing a passkey needs a confirmation engine

`removeCredential` and `setPasswordlessOnly` are **sudo-gated**: the server may
demand a fresh confirmation (`HTTP 401 PasskeyConfirmationRequired`). They route
through `frappe.passkeys.call`, which runs that confirmation and retries. On Desk and
on the app's portal pages `frappe.passkeys.call` is already wired. On a **bare** page
you wire it once from the pure engine and your own tiny modal:

```js
const C = frappe.passkeys_common;
const engine = C.createConfirmEngine({
  post: (method, body, headers) => fetch("/api/method/" + method, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Frappe-CSRF-Token": frappe.csrf_token },
    body: JSON.stringify(body || {}),
  }).then((r) => r.json().then((body) => ({ ok: r.ok, status: r.status, body }))),
  runGesture: (opts) => navigator.credentials
    .get({ publicKey: C.parseRequestOptionsFromJSON(opts) })
    .then((cred) => C.authAssertionToJSON(cred)),
  ui: makeYourConfirmModal,   // chooseMethod / collectPassword / announce / busy / done — your DOM
});
frappe.passkeys = frappe.passkeys || {};
frappe.passkeys.confirm = frappe.passkeys.confirm || engine.confirm;
frappe.passkeys.call = frappe.passkeys.call || engine.call;
```

`passkey_portal.bundle.js` is a full, self-contained reference implementation of
`makeYourConfirmModal` (a `role="dialog"` overlay with focus trap and Esc handling).

### Action confirmation for your own methods

The same engine gates any of *your* whitelisted methods. Decorate the server method
with `@passkey_protected("myapp.release_payment")` and call it with:

```js
await frappe.passkeys.call("myapp.api.release_payment", { payment_id });
// or resolve a grant yourself:  const grant = await frappe.passkeys.confirm("myapp.release_payment", { payment_id });
```

---

## Semantic markup contract

If you would rather **embed the app's barebones cards and only restyle them**, every
element the renderers emit carries a stable, semantic class hook and no opinionated
styling beyond what already ships (all colours are Frappe CSS variables). Style these;
do not depend on the DOM *nesting* staying identical.

**Cards** (`renderCards` / the portal `/passkeys` list):

| Hook | Element |
| --- | --- |
| `.passkey-cards-root`, `.passkey-card-list` | list container / `<ul role="list">` |
| `.passkey-card`, `.passkey-card-disabled` | a credential row (disabled variant) |
| `.passkey-card-glyph` | leading icon slot |
| `.passkey-card-label`, `.passkey-card-labelrow` | the credential name |
| `.passkey-badge`, `.passkey-badge-synced`, `.passkey-badge-device`, `.passkey-badge-disabled` | Synced / Device-bound / Disabled badges |
| `.passkey-card-meta`, `.passkey-card-provider`, `.passkey-card-created`, `.passkey-card-lastused` | provider + dates |
| `.passkey-card-flagged` | the security-flagged notice (`role="alert"`) |
| `.passkey-card-actions`, `.passkey-icon-btn` | the Rename / Remove buttons |
| `.passkey-card-add-row`, `.passkey-btn` | the "Add a passkey" row |
| `.passkey-empty`, `.passkey-empty-title`, `.passkey-empty-body` | the zero-passkeys hero |
| `.passkey-only-row`, `.passkey-only-label`, `.passkey-only-help`, `.passkey-only-toggle` | the passwordless switch |

**Login button + status** (`passkey_login.bundle.js`): `.btn-passkey-login`,
`.passkey-glyph`, `.passkey-label`, and the status line `.passkey-status`
(`--progress` / `--success` / `--error` tone modifiers, `__icon` / `__text` parts).

**Nudge banner**: `.passkey-nudge-banner`, `.passkey-nudge-title`,
`.passkey-nudge-copy`, `.passkey-nudge-acts`.

**The visually-hidden live region** (`.passkey-sr-only`) backs every announcement —
never `display:none` it; screen-reader users depend on it.

---

## Security invariants an integrator must not break

WebAuthn's security comes from the browser binding each assertion to the exact origin
that requested it. A custom UI keeps that intact by holding these lines:

1. **Serve over HTTPS.** WebAuthn only runs in a secure context (`localhost` is the
   one dev exception). Plain `http://` on any real host silently disables everything.
2. **Run the ceremony on the RP's own origin — never proxy or iframe it
   cross-origin.** `begin` → `navigator.credentials.get/create` → `verify` must all
   happen on an origin that matches the site's configured **RP ID / allowed origins**
   (see [`configuration.md`](configuration.md)). Relaying a ceremony through another
   origin either fails closed or *is* the phishing attack the technology exists to
   stop.
3. **Never cache, store, or replay a challenge.** `begin_*` responses are single-use
   and short-lived; the server consumes each one atomically. Always fetch fresh
   options for every attempt — never reuse `state_id`/`options`, and never re-POST an
   assertion (retry means a *new* ceremony).
4. **Keep requests same-origin and CSRF-safe.** Send `credentials: "same-origin"` and
   attach `X-Frappe-CSRF-Token: frappe.csrf_token` on authenticated POSTs (the
   headless transport does both for you). Guest login endpoints are CSRF-exempt but
   protected by an `HttpOnly` binder cookie the server sets and checks — so run the
   whole guest ceremony in the **same browser context**, first party.
5. **Don't invent existence signals.** Surface the generic failure copy; the server
   deliberately returns uniform errors so an attacker can't enumerate accounts or
   credentials. Do not branch your visible copy on anything that could reveal one.
6. **Let the server be the authority.** Client checks (capability, the last-method
   guard mirror in `passkey_manage_common`) are for UX only; every rule is enforced
   server-side. Trust its verdict, don't reimplement it.

---

## See also

- [`rest-api.md`](rest-api.md) — the raw endpoints, for a mobile app or a no-JS SPA.
- [`mobile-apps.md`](mobile-apps.md) — let a native iOS/Android app share the site's
  passkeys (Trusted App Origins + the two well-known files).
- [`configuration.md`](configuration.md) — the RP ID / origins your UI must serve from.
- [`security.md`](security.md) — the full security model.
