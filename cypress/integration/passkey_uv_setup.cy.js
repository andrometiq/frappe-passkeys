// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 5 — uv-setup inline step-up (DESIGN-v1 §3.4/§3.7). A credential born
// uv_initialized=0 (the conditional-create shape, forced server-side here) yields
// UVSetupRequired on a UV=1 assertion; the bundle opens a one-time password
// dialog (#passkey-uv-pwd), complete_uv_setup flips the bit and mints the
// session, and every later login is purely passwordless.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey uv-setup step-up", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
		cy.login(USER, PW());
		cy.visit("/app");
		cy.call("passkeys.tests.ui_test_helpers.make_uv_uninitialized", { user: USER });
		cy.call("logout");
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("repairs the credential via a one-time password, then logs in passwordlessly", () => {
		cy.visit("/login");
		cy.get("#passkey-login-btn").click();

		// UVSetupRequired → the step-up dialog with a password field appears
		cy.get(".passkey-dialog").should("have.attr", "role", "dialog");
		cy.get("#passkey-uv-pwd").should("be.visible").type(PW());
		cy.get(".passkey-dialog .btn-primary").click();

		// session minted for the repaired credential
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", USER);

		// and the flip is durable — a fresh passwordless login now needs no password
		cy.call("logout");
		cy.visit("/login");
		cy.get("#passkey-login-btn").click();
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", USER);
	});
});
