// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — accessibility of the management surfaces (DESIGN-v1 §5.5/§12.4). Cards
// use list semantics; icon-only actions carry accessible names ("Rename passkey
// ⟨label⟩" / "Delete passkey ⟨label⟩"); badges have text equivalents; a polite
// live region announces async outcomes; dialogs trap + return focus and are
// Esc-dismissable.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey management — accessibility", () => {
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

	it("exposes list semantics + accessibly-named icon actions + a text badge", () => {
		cy.visit("/app/user/" + USER);
		cy.get(".passkey-card-list", { timeout: 20000 }).should("have.attr", "role", "list");
		cy.get(".passkey-card .passkey-rename")
			.should("have.attr", "aria-label")
			.and("match", /^Rename passkey /);
		cy.get(".passkey-card .passkey-delete")
			.should("have.attr", "aria-label")
			.and("match", /^Delete passkey /);
		// the glyph is decorative
		cy.get(".passkey-card-glyph").first().should("have.attr", "aria-hidden", "true");
		// badge carries a text equivalent, not colour alone
		cy.get(".passkey-card .passkey-badge").first().invoke("text").should("match", /\w/);
	});

	it("has a polite live region for async announcements", () => {
		cy.visit("/app/user/" + USER);
		cy.get(".passkey-sr-only", { timeout: 20000 })
			.should("exist")
			.and("have.attr", "aria-live", "polite");
	});

	it("navbar dialog returns focus to the invoking control on Esc", () => {
		cy.visit("/app");
		cy.get("#passkey-navbar-item", { timeout: 20000 }).click({ force: true });
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get("body").type("{esc}");
		cy.get(".modal-dialog").should("not.be.visible");
		// focus returns to the opener (frappe.ui.Dialog restores it)
		cy.focused().should("have.id", "passkey-navbar-item");
	});
});
