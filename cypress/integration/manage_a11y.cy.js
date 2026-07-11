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

function getNativePasskeysEntry() {
	// v16/develop expose "My Passkeys" as a native Navbar Settings item; v15 has no
	// idempotent core sync so the desk bundle injects the #passkey-navbar-item DOM
	// fallback instead (see install.sync_standard_navbar_items). Accept either.
	return cy.window().then((win) => {
		const dropdown =
			win.frappe.boot.navbar_settings && win.frappe.boot.navbar_settings.settings_dropdown;
		const item = Array.isArray(dropdown)
			? dropdown.find((candidate) => candidate.item_label === "My Passkeys")
			: undefined;
		if (item) {
			expect(win.frappe.utils.eval(item.condition), "My Passkeys condition").to.equal(true);
			return cy.wrap(item, { log: false });
		}
		return cy.get("#passkey-navbar-item", { timeout: 10000 }).should("exist").then(() => null);
	});
}

function openNativePasskeysEntry() {
	return getNativePasskeysEntry().then(() => {
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

	it("desk user-menu action opens an Esc-dismissable dialog", () => {
		cy.visit_desk(USER);
		openNativePasskeysEntry();
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.window().its("cur_dialog.display", { timeout: 10000 }).should("eq", true);
		pressEscapeOnTopModal();
		cy.get(".modal-dialog").should("not.be.visible");
	});
});
