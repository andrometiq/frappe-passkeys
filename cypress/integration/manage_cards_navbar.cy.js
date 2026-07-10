// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — the desk "My Passkeys" surface (DESIGN-v1 §8.1, F3-9). On develop the
// supported entry lives in Frappe's user menu settings dropdown, rendered from
// Navbar Settings via frappe.ui.create_menu; older desks may still expose the same
// entry through the classic top navbar.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

function assertNativePasskeysEntryRegistered() {
	return cy.window().should((win) => {
		expect(win.frappe.boot.navbar_settings.settings_dropdown, "settings dropdown items").to.be.an("array");
	}).then((win) => {
		const items = win.frappe.boot.navbar_settings.settings_dropdown;
		const item = items.find((candidate) => candidate.item_label === "My Passkeys");
		expect(item, "My Passkeys standard navbar item").to.exist;
		expect(item.item_type).to.equal("Action");
		expect(item.action).to.contain("frappe.passkeys.manage.openManagerDialog");
		expect(win.frappe.utils.eval(item.condition), "My Passkeys condition").to.equal(true);
		return item;
	});
}

function openNativePasskeysEntry() {
	return assertNativePasskeysEntryRegistered().then(() => {
		cy.get("body").then(($body) => {
			if ($body.find("#passkey-navbar-item:visible").length) {
				cy.get("#passkey-navbar-item:visible").click();
				return;
			}
			if ($body.find(".dropdown-navbar-user").length) {
				cy.get(".dropdown-navbar-user").last().trigger("click");
				return;
			}
			if ($body.find(".sidebar-header").length) {
				cy.get(".sidebar-header").first().click({ force: true });
				return;
			}
			cy.get(".dropdown-toggle:visible").last().click();
		});
		cy.get(".frappe-menu.context-menu:visible, .dropdown-menu:visible", { timeout: 10000 })
			.should("contain.text", "My Passkeys")
			.then(($menu) => {
				const item = Array.from($menu.find(".dropdown-menu-item")).find((el) =>
					el.textContent.includes("My Passkeys")
				);
				expect(item, "visible My Passkeys menu item").to.exist;
				item.click();
			});
	});
}

chromium_only("passkey management — navbar dialog", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("registers a native My Passkeys item in the user-menu settings dropdown", () => {
		cy.visit_desk(USER);
		assertNativePasskeysEntryRegistered();
	});

	it("opens a dialog showing the card component", () => {
		cy.visit_desk(USER);
		openNativePasskeysEntry();
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog .modal-title").should("contain.text", "My Passkeys");
		cy.get(".modal-dialog .passkey-card").should("have.length.greaterThan", 0);
	});
});
