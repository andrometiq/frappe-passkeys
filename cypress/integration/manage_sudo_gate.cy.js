// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — the sudo-gated delete dance (DESIGN-v1 §7.4/§8.3). Deleting a
// credential requires a live full-sudo window; when the window is cold, the
// server answers the §7.2 PasskeyConfirmationRequired contract and the client runs
// a passkeys.manage confirmation (passkey-first, password fallback) before
// retrying. Needs a test helper to expire the fresh-login window — see the manifest.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const CLEAR_SUDO = "passkeys.tests.ui_test_helpers.clear_sudo_window";

chromium_only("passkey management — sudo-gated delete", () => {
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

	it("deletes without a re-prompt while the fresh-login sudo window is live", () => {
		cy.login(USER, PW()); // fresh window
		cy.register_passkey(USER, PW()); // a second credential so the last-method guard doesn't fire
		cy.login(USER, PW());
		cy.visit("/app/user/" + USER);
		cy.get(".passkey-card", { timeout: 20000 }).should("have.length", 2);
		cy.get(".passkey-card .passkey-delete").first().click();
		cy.get(".modal-dialog .btn-primary").contains("Remove passkey").click();
		cy.get(".passkey-card", { timeout: 20000 }).should("have.length", 1);
	});

	it("prompts a passkey confirmation when the sudo window is cold, then completes", () => {
		cy.login(USER, PW());
		cy.register_passkey(USER, PW()); // ensure >=2 so last-method guard is clear
		cy.login(USER, PW());
		cy.visit("/app/user/" + USER);
		// expire the fresh-login window so delete must re-confirm (§7.4)
		cy.call(CLEAR_SUDO, {});
		cy.get(".passkey-card .passkey-delete", { timeout: 20000 }).first().click();
		cy.get(".modal-dialog .btn-primary").contains("Remove passkey").click();
		// the sudo dance dialog appears — a passkeys.manage confirmation
		cy.get(".passkey-confirm-passkey", { timeout: 20000 }).should("be.visible").click();
		// virtual authenticator auto-UV completes the ceremony → credential removed
		cy.get(".passkey-card", { timeout: 20000 }).should("have.length", 1);
	});
});
