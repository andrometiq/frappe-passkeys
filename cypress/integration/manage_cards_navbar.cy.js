// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — the navbar "My Passkeys" surface (DESIGN-v1 §8.1, F3-9). The desk
// bundle injects a "My Passkeys" item into the navbar user dropdown; clicking it
// opens the same card component in a dialog (management without knowing the User
// form exists; FIDO principle 8 prominence).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey management — navbar dialog", () => {
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

	it("injects a My Passkeys item into the navbar user dropdown", () => {
		cy.visit("/app");
		cy.get("#passkey-navbar-item", { timeout: 20000 }).should("exist").and("contain.text", "My Passkeys");
	});

	it("opens a dialog showing the card component", () => {
		cy.visit("/app");
		cy.get("#passkey-navbar-item", { timeout: 20000 }).click({ force: true });
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog .modal-title").should("contain.text", "My Passkeys");
		cy.get(".modal-dialog .passkey-card").should("have.length.greaterThan", 0);
	});
});
