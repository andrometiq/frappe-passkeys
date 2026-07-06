// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Cypress support commands for the P3 passwordless-login specs (DESIGN-v1
// §12.3/§12.4). Two families:
//   1. CDP WebAuthn virtual-authenticator drivers (ported verbatim in intent
//      from spikes/cypress-virtual-authenticator/commands.js; Chromium-only).
//   2. Frappe idiom (`cy.login`, `cy.call`) + higher-level app helpers that seed
//      a real resident credential through the committed registration ceremony,
//      so the login specs assert an end-to-end round trip with no key injection.
//
// Chromium-family browsers only. Specs guard with Cypress.isBrowser({family}).

// ---------------------------------------------------------------------------
// Low-level CDP bridge (NOTES.md §3) — undocumented but long-lived.
// ---------------------------------------------------------------------------
const cdp = (command, params = {}) =>
	Cypress.automation("remote:debugger:protocol", { command, params });

let current_authenticator_id = null;

// Platform passkey: discoverable ES256, UV supported + passing, presence auto.
const DEFAULT_AUTHENTICATOR_OPTIONS = {
	protocol: "ctap2",
	ctap2Version: "ctap2_1",
	transport: "internal",
	hasResidentKey: true,
	hasUserVerification: true,
	isUserVerified: true,
	automaticPresenceSimulation: true,
	defaultBackupEligibility: false,
	defaultBackupState: false,
};

// ---------------------------------------------------------------------------
// Virtual-authenticator lifecycle
// ---------------------------------------------------------------------------
Cypress.Commands.add("enable_virtual_authenticator", (options = {}) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.enable", { enableUI: false })
			.then(() =>
				cdp("WebAuthn.addVirtualAuthenticator", {
					options: { ...DEFAULT_AUTHENTICATOR_OPTIONS, ...options },
				})
			)
			.then(({ authenticatorId }) => {
				current_authenticator_id = authenticatorId;
				return authenticatorId;
			})
	)
);

Cypress.Commands.add("disable_virtual_authenticator", () =>
	cy.wrap(null, { log: false }).then(() => {
		const remove = current_authenticator_id
			? cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: current_authenticator_id })
			: Promise.resolve();
		return remove
			.catch(() => {})
			.then(() => {
				current_authenticator_id = null;
				return cdp("WebAuthn.disable").catch(() => {});
			});
	})
);

Cypress.Commands.add("remove_virtual_authenticator", () =>
	cy.wrap(null, { log: false }).then(() => {
		if (!current_authenticator_id) return null;
		const id = current_authenticator_id;
		current_authenticator_id = null;
		return cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: id });
	})
);

// ---------------------------------------------------------------------------
// Presence ("tap") + UV knobs
// ---------------------------------------------------------------------------
Cypress.Commands.add("hold_passkey_taps", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.setAutomaticPresenceSimulation", {
			authenticatorId: id || current_authenticator_id,
			enabled: false,
		})
	)
);

Cypress.Commands.add("simulate_passkey_tap", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.setAutomaticPresenceSimulation", {
			authenticatorId: id || current_authenticator_id,
			enabled: true,
		})
	)
);

Cypress.Commands.add("set_user_verified", (is_user_verified, id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.setUserVerified", {
			authenticatorId: id || current_authenticator_id,
			isUserVerified: !!is_user_verified,
		})
	)
);

Cypress.Commands.add("get_virtual_credentials", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.getCredentials", { authenticatorId: id || current_authenticator_id }).then(
			({ credentials }) => credentials
		)
	)
);

Cypress.Commands.add("clear_virtual_credentials", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.clearCredentials", { authenticatorId: id || current_authenticator_id })
	)
);

// ---------------------------------------------------------------------------
// Frappe idiom (mirrors frappe/cypress/support/commands.js)
// ---------------------------------------------------------------------------
Cypress.Commands.add("login", (email, password) => {
	if (!email) email = Cypress.config("testUser") || "Administrator";
	if (!password) password = Cypress.env("adminPassword") || "admin";
	return cy.request({
		url: "/api/method/login",
		method: "POST",
		body: { usr: email, pwd: password },
	});
});

Cypress.Commands.add("call", (method, args) =>
	cy
		.window()
		.its("frappe.csrf_token")
		.then((csrf_token) =>
			cy
				.request({
					url: `/api/method/${method}`,
					method: "POST",
					body: args,
					headers: { "X-Frappe-CSRF-Token": csrf_token, Accept: "application/json" },
				})
				.then((res) => res.body)
		)
);

// ---------------------------------------------------------------------------
// App helpers
// ---------------------------------------------------------------------------

// RP ID = the site host, expected origin = the site origin — both derived from
// the CI-injected baseUrl so the specs work on any site name (passkeys.localhost
// locally, test_site on CI). The RP ID must equal the origin host for the
// browser ceremony to succeed.
const site_origin = () => new URL(Cypress.config("baseUrl")).origin;
const site_host = () => new URL(Cypress.config("baseUrl")).hostname;

// Configure Passkey Settings for this test site.
Cypress.Commands.add("setup_passkey_settings", (opts = {}) =>
	cy.call("passkeys.tests.ui_test_helpers.configure_login", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: 1,
		passkey_as_second_factor: opts.second_factor ? 1 : 0,
	})
);

Cypress.Commands.add("disable_passkey_login", () =>
	cy.call("passkeys.tests.ui_test_helpers.configure_login", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: 0,
		passkey_as_second_factor: 0,
	})
);

Cypress.Commands.add("purge_server_passkeys", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.purge_passkeys", { user })
);

// --- second-factor (P4, §6) scaffolding ------------------------------------
// Turn on core 2FA (the structural floor) + passkey_as_second_factor, pointed at
// this UI-test origin. `first_factor`/`otp_fallback` toggle the co-features.
Cypress.Commands.add("setup_second_factor", (opts = {}) =>
	cy.call("passkeys.tests.ui_test_helpers.configure_second_factor", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: opts.first_factor ? 1 : 0,
		allow_otp_fallback: opts.otp_fallback ? 1 : 0,
	})
);

Cypress.Commands.add("teardown_second_factor", () =>
	cy.call("passkeys.tests.ui_test_helpers.teardown_second_factor", {})
);

// A non-admin user with a known password (the passkey second factor is hard-
// exempt for Administrator, §6.2).
Cypress.Commands.add("ensure_sf_user", (email, pwd) =>
	cy.call("passkeys.tests.ui_test_helpers.ensure_second_factor_user", { email, pwd })
);

// Cover the user with a core-2FA role (call AFTER registering the passkey).
Cypress.Commands.add("enroll_user_2fa", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.enroll_user_in_2fa", { user })
);

Cypress.Commands.add("delete_test_user", (email) =>
	cy.call("passkeys.tests.ui_test_helpers.delete_test_user", { email })
);

// Seed a real discoverable credential for `user`: log in over the password leg
// (which seeds a sudo window), drive the committed registration ceremony from
// the page (virtual authenticator generates the ES256 key — no injection), then
// log out. Leaves a resident credential on the authenticator AND a server row,
// so the subsequent login specs are a true end-to-end round trip.
Cypress.Commands.add("register_passkey", (user, password) => {
	cy.login(user, password);
	// Visit a Desk page so window.frappe (+ csrf_token + the JSON shim) exist.
	cy.visit("/app");
	cy.window().its("frappe").should("exist");
	cy.window().then((win) =>
		win.frappe
			.call("passkeys.api.registration.begin_registration", { flow: "explicit" })
			.then((r) => {
				const opts = r.message.options;
				// Parse the L3 JSON options → CredentialCreationOptions, add the
				// credProps extension exactly as the bundle does (§3.5).
				const create_opts = win.PublicKeyCredential.parseCreationOptionsFromJSON(opts);
				create_opts.extensions = { ...(create_opts.extensions || {}), credProps: true };
				return navigator.credentials
					.create({ publicKey: create_opts })
					.then((cred) =>
						win.frappe.call("passkeys.api.registration.verify_registration", {
							state_id: r.message.state_id,
							credential: JSON.stringify(cred.toJSON()),
						})
					);
			})
	);
	cy.call("logout");
});
