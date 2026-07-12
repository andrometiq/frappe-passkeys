// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// The sudo-gated delete dance. Deleting a
// credential requires a live full-sudo window; when the window is cold, the
// server answers the PasskeyConfirmationRequired contract and the client runs
// a passkeys.manage confirmation (passkey-first, password fallback) before
// retrying. Needs a test helper to expire the fresh-login window — see the manifest.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const CLEAR_SUDO = "passkeys.tests.ui_test_helpers.clear_sudo_window";

const visit_user_passkeys = () => {
	cy.visit_desk(USER);
	cy.window().its("cur_frm.doc.name", { timeout: 20000 }).should("eq", USER);
	cy.document().then((doc) => {
		// The Passkeys section lives in the Settings tab now (right after the password
		// area), not the Connections tab.
		const tabs = Array.from(doc.querySelectorAll("a, button, [role='tab']"));
		const tab = tabs.find(
			(el) =>
				(el.textContent || "").trim() === "Settings" ||
				el.getAttribute("href") === "#user-settings_tab" ||
				el.getAttribute("data-target") === "#user-settings_tab" ||
				el.getAttribute("data-bs-target") === "#user-settings_tab" ||
				el.getAttribute("aria-controls") === "user-settings_tab"
		);
		expect(tab, "Settings tab").to.exist;
		tab.click();
	});
	cy.get("#user-settings_tab", { timeout: 20000 }).should("be.visible");
};

const own_passkey_root = () => cy.get(".passkey-cards-root:visible", { timeout: 20000 }).last();

chromium_only("passkey management — sudo-gated delete", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
	});

	beforeEach(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.clear_virtual_credentials();
		cy.register_passkey(USER, PW());
		cy.clear_virtual_credentials();
		cy.register_passkey(USER, PW());
		cy.login(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("deletes without a re-prompt while the fresh-login sudo window is live", () => {
		cy.login(USER, PW()); // fresh window
		visit_user_passkeys();
		own_passkey_root().find(".passkey-card", { timeout: 20000 }).should("have.length", 2);
		own_passkey_root().find(".passkey-card .passkey-delete").first().click();
		cy.get(".modal-dialog .btn-primary").contains("Remove passkey").click();
		own_passkey_root().find(".passkey-card", { timeout: 20000 }).should("have.length", 1);
	});

	it("prompts a passkey confirmation when the sudo window is cold, then completes", () => {
		cy.login(USER, PW());
		visit_user_passkeys();
		// expire the fresh-login window so delete must re-confirm
		cy.call(CLEAR_SUDO, {});
		own_passkey_root().find(".passkey-card .passkey-delete", { timeout: 20000 }).first().click();
		cy.get(".modal-dialog .btn-primary").contains("Remove passkey").click();
		// the sudo dance dialog appears — a passkeys.manage confirmation
		cy.get(".passkey-confirm-passkey", { timeout: 20000 }).should("be.visible").click();
		// virtual authenticator auto-UV completes the ceremony → credential removed
		own_passkey_root().find(".passkey-card", { timeout: 20000 }).should("have.length", 1);
	});
});
