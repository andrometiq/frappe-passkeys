// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 1 — J1 conditional-UI (autofill) passwordless login (DESIGN-v1 §3.1,
// §5.2). A discoverable UV credential is seeded through the committed
// registration ceremony (virtual authenticator generates the ES256 key); the
// login page patches #login_email to `autocomplete="username webauthn"` and arms
// a `mediation:"conditional"` get() that, with presence auto-simulated, resolves
// to verify_login and a redirect to the returned home_page.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey conditional-UI login", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("patches the username field for webauthn autofill", () => {
		cy.visit("/login");
		cy.get("#login_email").should("have.attr", "autocomplete").and("contain", "webauthn");
	});

	it("resolves the conditional ceremony into a passwordless session", () => {
		// A resident credential is present + presence is auto-simulated, so the
		// pending conditional get() completes unaided (NOTES.md §7b strategy B /
		// assumption A1). Deterministic fallback if A1 is false on a runner: the
		// explicit-button spec exercises the same verify_login path via modal get().
		cy.visit("/login");
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", USER);
	});
});
