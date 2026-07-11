// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// The desk "My Passkeys" surface. On develop the
// supported entry lives in Frappe's user menu settings dropdown, rendered from
// Navbar Settings via frappe.ui.create_menu; older desks may still expose the same
// entry through the classic top navbar.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
// The desk user-menu dropdown DOM varies across Frappe versions (upstream, not this
// app). Exercise the full menu-navigation-to-dialog only where that menu is current and
// stable; CI passes the Frappe branch as CYPRESS_frappeBranch. The native-entry
// registration check below still runs on all versions.
const navMenu = (Cypress.env("frappeBranch") || "develop") === "develop" ? it : it.skip;

function assertNativePasskeysEntryRegistered() {
	// The "My Passkeys" desk entry is reachable one of two ways, by Frappe version:
	// v16/develop sync it as a native Navbar Settings item; v15 has no idempotent
	// core sync (see install.sync_standard_navbar_items) so the desk bundle injects
	// the #passkey-navbar-item DOM fallback instead. Accept either.
	return cy.window().then((win) => {
		const dropdown =
			win.frappe.boot.navbar_settings && win.frappe.boot.navbar_settings.settings_dropdown;
		const item = Array.isArray(dropdown)
			? dropdown.find((candidate) => candidate.item_label === "My Passkeys")
			: undefined;
		if (item) {
			expect(item.item_type).to.equal("Action");
			expect(item.action).to.contain("frappe.passkeys.manage.openManagerDialog");
			expect(win.frappe.utils.eval(item.condition), "My Passkeys condition").to.equal(true);
			return cy.wrap(item, { log: false });
		}
		return cy.get("#passkey-navbar-item", { timeout: 10000 }).should("exist").then(() => null);
	});
}

// The desk user menu is wired by frappe.ui.create_menu during desk boot, so its
// toggle can be in the DOM before its click handler is bound — a single force-click
// is then silently lost (visit_desk only waits for the `frappe` global, not a fully
// booted sidebar). Click the visible user-menu toggle, re-clicking until the menu
// opens (bounded), which removes that boot-race flake. develop exposes the toggle as
// .sidebar-user-button in the sidebar; older desks use the classic navbar toggle.
function openUserMenu(attempt = 0) {
	const MENU = ".frappe-menu.context-menu:visible, .dropdown-menu:visible";
	return cy.get("body").then(($body) => {
		if ($body.find(MENU).length) return; // already open — don't toggle it shut
		const toggle =
			[
				".sidebar-user-button:visible",
				".dropdown-navbar-user:visible",
				".sidebar-header:visible",
				".dropdown-toggle:visible",
			].find((sel) => $body.find(sel).length) || ".dropdown-toggle:visible";
		cy.get(toggle).first().click({ force: true });
		if (attempt >= 5) return; // stop re-clicking; the caller's assertion reports failure
		return cy.wait(400, { log: false }).then(() => openUserMenu(attempt + 1));
	});
}

function openNativePasskeysEntry() {
	return assertNativePasskeysEntryRegistered().then(() => {
		return cy.get("body").then(($body) => {
			// v15 DOM fallback: a direct navbar button that opens the manager dialog
			// itself — there is NO dropdown menu to traverse, so return here.
			if ($body.find("#passkey-navbar-item:visible").length) {
				cy.get("#passkey-navbar-item:visible").click();
				return;
			}
			// Native Navbar Settings item: open the user menu, then click the item.
			openUserMenu();
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

	navMenu("opens a dialog showing the card component", () => {
		cy.visit_desk(USER);
		openNativePasskeysEntry();
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog .modal-title").should("contain.text", "My Passkeys");
		cy.get(".modal-dialog .passkey-card").should("have.length.greaterThan", 0);
	});
});
