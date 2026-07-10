// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — credential-management cards on the Desk User form (DESIGN-v1 §8.1/§8.2).
// The user's own User form grows a "Passkeys" section with one card per credential
// (label + Synced/Device-bound badge + rename/delete), plus add + empty state. The
// card component is frappe.passkeys.manage.renderCards; rename is display-only (no
// sudo), delete is confirm + sudo-gated (§7.4).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

const visit_user_passkeys = () => {
	cy.visit_desk(USER);
	cy.window().its("cur_frm.doc.name", { timeout: 20000 }).should("eq", USER);
	cy.document().then((doc) => {
		const tabs = Array.from(doc.querySelectorAll("a, button, [role='tab']"));
		const tab = tabs.find(
			(el) =>
				(el.textContent || "").trim() === "Connections" ||
				el.getAttribute("href") === "#user-connections_tab" ||
				el.getAttribute("data-target") === "#user-connections_tab" ||
				el.getAttribute("data-bs-target") === "#user-connections_tab" ||
				el.getAttribute("aria-controls") === "user-connections_tab"
		);
		expect(tab, "Connections tab").to.exist;
		tab.click();
	});
	cy.get("#user-connections_tab", { timeout: 20000 }).should("be.visible");
};

const own_passkey_root = () => cy.get(".passkey-cards-root:visible", { timeout: 20000 }).last();

chromium_only("passkey management — User form cards", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("shows the empty state with a Create-a-passkey hero when there are no passkeys", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		visit_user_passkeys();
		own_passkey_root().within(() => {
			cy.get(".passkey-empty", { timeout: 20000 }).should("exist");
			cy.get(".passkey-empty-title").should("contain.text", "Create a passkey");
			cy.get(".passkey-empty-cta").should("be.visible");
		});
	});

	it("renders a card per credential with an accessible label + Synced/Device-bound badge", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.clear_virtual_credentials();
		cy.register_passkey(USER, PW());
		cy.login(USER, PW()); // fresh login ⇒ live sudo window for later mutations
		visit_user_passkeys();
		own_passkey_root().within(() => {
			cy.get(".passkey-card", { timeout: 20000 }).should("have.length", 1);
			cy.get(".passkey-card .passkey-badge").first().should(($b) => {
				expect($b.text().trim()).to.be.oneOf(["Synced", "Device-bound"]);
			});
			cy.get(".passkey-card .passkey-rename")
				.should("have.attr", "aria-label")
				.and("match", /^Rename passkey /);
			cy.get(".passkey-card .passkey-delete")
				.should("have.attr", "aria-label")
				.and("match", /^Delete passkey /);
		});
	});

	it("renames a credential inline (display-only, no sudo prompt)", () => {
		visit_user_passkeys();
		own_passkey_root().find(".passkey-card .passkey-rename", { timeout: 20000 }).first().click();
		cy.get(".modal-dialog input[data-fieldname='label'], .modal-dialog input")
			.first()
			.clear()
			.type("My laptop");
		cy.get(".modal-dialog .btn-primary").contains("Save").click();
		own_passkey_root().find(".passkey-card .passkey-card-label", { timeout: 20000 }).should("contain.text", "My laptop");
	});
});
