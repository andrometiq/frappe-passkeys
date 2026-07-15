// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// uv-setup inline step-up. A credential born
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
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.call("passkeys.tests.ui_test_helpers.make_uv_uninitialized", { user: USER });
		cy.clear_password_failures(USER);
		// This spec runs late in the suite; the shared CI runner IP has been hitting
		// the 30/min guest begin_login limit across earlier specs. Reset it (while still
		// authed) so the step-up ceremony below starts with a fresh budget instead of 429ing.
		cy.call("passkeys.tests.ui_test_helpers.clear_guest_ceremony_rate_limit");
		cy.call("logout");
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("repairs the credential via a one-time password, then logs in passwordlessly", () => {
		cy.stub_post_login_shell();
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();

		// UVSetupRequired → the step-up dialog with a password field appears
		cy.get(".passkey-dialog").should("have.attr", "role", "dialog");
		cy.get("#passkey-uv-pwd").should("be.visible").type(PW());
		cy.intercept_frappe_method("passkeys.passkey.complete_uv_setup", "complete_uv_setup");
		cy.get(".passkey-dialog .btn-primary").click();

		// session minted for the repaired credential
		cy.wait("@complete_uv_setup", { timeout: 20000 })
			.its("response.statusCode")
			.should("be.within", 200, 299);
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);

		// and the flip is durable — a fresh passwordless login now needs no password
		cy.call("logout");
		cy.stub_post_login_shell();
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_login");
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();
		cy.wait("@verify_login", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});
});
