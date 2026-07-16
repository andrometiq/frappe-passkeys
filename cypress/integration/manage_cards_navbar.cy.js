// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Regression guard that the old "My Passkeys" navbar entry is GONE — both the item
// the app used to sync into Navbar Settings and the legacy DOM-injected fallback.
// The management home (list / add / rename / remove on the User form) is covered by
// manage_user_form.cy.js.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey management — navbar entry removed", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings(); // enable a mode so frappe.boot.passkeys exists
	});

	beforeEach(() => {
		cy.login(USER, PW());
	});

	after(() => {
		cy.clearCookies();
	});

	it("no longer syncs a 'My Passkeys' item into the Navbar Settings dropdown", () => {
		cy.visit_desk(USER);
		cy.window().then((win) => {
			// The app is enabled (boot.passkeys present) but must NOT contribute a navbar item.
			expect(win.frappe.boot.passkeys, "passkeys boot payload").to.exist;
			const dropdown =
				(win.frappe.boot.navbar_settings && win.frappe.boot.navbar_settings.settings_dropdown) || [];
			const item = dropdown.find((candidate) => candidate.item_label === "My Passkeys");
			expect(item, "a synced My Passkeys navbar item").to.equal(undefined);
		});
	});

	it("does not DOM-inject the legacy #passkey-navbar-item fallback", () => {
		cy.visit_desk(USER);
		// give the desk bundle's boot hook time to run; the element must never appear
		cy.wait(1500, { log: false });
		cy.get("body").find("#passkey-navbar-item").should("have.length", 0);
	});
});
