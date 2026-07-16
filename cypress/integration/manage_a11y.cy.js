// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Accessibility of the management surfaces. Cards
// use list semantics; icon-only actions carry accessible names ("Rename passkey
// ⟨label⟩" / "Delete passkey ⟨label⟩"); badges have text equivalents; a polite
// live region announces async outcomes; dialogs trap + return focus and are
// Esc-dismissable.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

function pressEscapeOnTopModal() {
	cy.get(".modal.show", { timeout: 10000 }).trigger("keydown", {
		key: "Escape",
		code: "Escape",
		keyCode: 27,
		which: 27,
		bubbles: true,
		force: true,
	});
}

chromium_only("passkey management — accessibility", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	beforeEach(() => {
		cy.login(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
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

	// "My Passkeys" is no longer a navbar entry (it lives in the User-form section), but
	// openManagerDialog() is retained for programmatic CTAs/nudges — exercise the
	// dialog's a11y (visible, titled, Esc-dismissable) via that entry point. Version-
	// independent, so it runs on every Frappe branch.
	it("the manager dialog (opened programmatically, e.g. from a CTA) is Esc-dismissable", () => {
		cy.visit_desk(USER);
		cy.window().then((win) => win.frappe.passkeys.manage.openManagerDialog());
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog .modal-title").should("contain.text", "My Passkeys");
		cy.window().its("cur_dialog.display", { timeout: 10000 }).should("eq", true);
		pressEscapeOnTopModal();
		cy.get(".modal-dialog").should("not.be.visible");
	});
});
