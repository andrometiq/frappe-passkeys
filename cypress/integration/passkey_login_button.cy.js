// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 2 — J2 explicit "Sign in with a passkey" button (DESIGN-v1 §5.2). The
// button is always shown when a passkey login mode is enabled + WebAuthn is
// detected; clicking it runs a modal get() (allowCredentials empty, discoverable)
// → verify_login → redirect. When all modes are off, begin_login answers
// `enabled:false` and the bundle removes itself → no button.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey explicit-button login", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.setup_passkey_settings(); // re-enable (the disabled-mode test turns it off)
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("shows an accessible button mounted as the first alternate method", () => {
		cy.visit("/login");
		cy.get("#passkey-login-btn")
			.should("be.visible")
			.and("have.text", "Sign in with a passkey")
			.and(($b) => {
				expect($b.attr("type"), "button type").to.eq("button");
			});
		// first alternate-method control on the card
		cy.get(".btn-login-option").first().should("have.id", "passkey-login-btn");
	});

	it("completes a passwordless session on click", () => {
		cy.visit("/login");
		cy.get("#passkey-login-btn").click();
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", USER);
	});

	it("removes itself when every login mode is off", () => {
		cy.disable_passkey_login();
		cy.visit("/login");
		cy.get("#login_email").should("exist"); // page rendered
		cy.get("#passkey-login-btn").should("not.exist");
	});
});
