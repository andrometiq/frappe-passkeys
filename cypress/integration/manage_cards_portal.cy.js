// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — the /passkeys portal management page (DESIGN-v1 §8.1). Website users
// get the same card component from passkey_portal.bundle.js, rendered into
// #passkey-portal-root. Guests are redirected to /login (server controller). The
// portal delete path reuses the confirm engine's sudo dance (§7.4) with a
// self-contained modal (portal has no frappe.ui.Dialog).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey management — portal /passkeys", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("mounts the card component into #passkey-portal-root", () => {
		cy.visit("/passkeys");
		cy.get("#passkey-portal-root", { timeout: 20000 }).should("exist");
		// no credentials yet ⇒ empty-state hero
		cy.get("#passkey-portal-root .passkey-empty", { timeout: 20000 }).should("exist");
	});

	it("renders a card once a credential exists", () => {
		cy.register_passkey(USER, PW());
		cy.login(USER, PW());
		cy.visit("/passkeys");
		cy.get("#passkey-portal-root .passkey-card", { timeout: 20000 }).should("have.length", 1);
		cy.get("#passkey-portal-root .passkey-card .passkey-delete")
			.should("have.attr", "aria-label")
			.and("match", /^Delete passkey /);
	});

	it("redirects a guest to the login page", () => {
		cy.clearCookies();
		cy.visit("/passkeys");
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/login/);
	});
});
