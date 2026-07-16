// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Graceful degradation. A non-200 begin_login
// (429 / 5xx / network error) must leave the password form fully usable with NO
// passkey button and NO error message — the login page is never deadened by a
// passkey outage.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login degradation", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.call("logout");
	});

	after(() => cy.clearCookies());

	it("stays a usable password login when begin_login 500s", () => {
		cy.intercept("POST", "**/passkeys.passkey.begin_login", { statusCode: 500, body: {} }).as("begin");
		cy.visit_login();
		cy.wait("@begin");
		cy.get("#passkey-login-btn").should("not.exist");
		cy.get(".login-error-banner:visible").should("not.exist");
		// password login still works end to end
		cy.stub_post_login_shell();
		// Core's login form posts to /login on v15 and /api/method/login on v16+;
		// match both so the password-fallback contract is verified on every version.
		cy.intercept("POST", "**/login").as("password_login");
		cy.get("#login_email").type(USER);
		cy.get("#login_password").type(PW());
		cy.get(".form-login .btn-login, .btn-login").first().click();
		cy.wait("@password_login").its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});

	it("stays usable on a begin_login network failure", () => {
		cy.intercept("POST", "**/passkeys.passkey.begin_login", { forceNetworkError: true }).as("begin_ne");
		cy.visit_login();
		cy.wait("@begin_ne").should((interception) => {
			expect(interception.error, "begin_login network error").to.exist;
		});
		cy.get("#login_email").should("be.visible");
		cy.get("#passkey-login-btn").should("not.exist");
		cy.get(".login-error-banner:visible").should("not.exist");
	});
});
