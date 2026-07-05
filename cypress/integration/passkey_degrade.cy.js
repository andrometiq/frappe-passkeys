// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 9 — graceful degradation (DESIGN-v1 §5.2, B-F5). A non-200 begin_login
// (429 / 5xx / network error) must leave the password form fully usable with NO
// passkey button and NO error message — the login page is never deadened by a
// passkey outage.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login degradation", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.call("logout");
	});

	after(() => cy.clearCookies());

	it("stays a usable password login when begin_login 500s", () => {
		cy.intercept("POST", "**/passkeys.passkey.begin_login", { statusCode: 500, body: {} }).as("begin");
		cy.visit("/login");
		cy.wait("@begin");
		cy.get("#passkey-login-btn").should("not.exist");
		cy.get(".login-error-banner:visible").should("not.exist");
		// password login still works end to end
		cy.get("#login_email").type(USER);
		cy.get("#login_password").type(PW());
		cy.get(".form-login .btn-login, .btn-login").first().click();
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
	});

	it("stays usable on a begin_login network failure", () => {
		cy.call("logout");
		cy.intercept("POST", "**/passkeys.passkey.begin_login", { forceNetworkError: true }).as("begin_ne");
		cy.visit("/login");
		cy.get("#login_email").should("be.visible");
		cy.get("#passkey-login-btn").should("not.exist");
		cy.get(".login-error-banner:visible").should("not.exist");
	});
});
