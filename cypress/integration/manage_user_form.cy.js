// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Credential-management on the Desk User form: the "Passkeys" section (a Custom
// Field Section Break + HTML wrapper in the Settings tab, installed by
// install.sync_user_form_section) renders one card per credential (label +
// Synced/Device-bound badge + rename/delete) plus add + empty state. Rename is
// display-only; delete is confirm + sudo-gated (a cold sudo window triggers a
// passkeys.manage confirmation before the delete retries).

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
	// The "Passkeys" section is collapsible and renders collapsed by default
	// (install.py marks the Section Break collapsible: 1). Expand it — only if it is
	// currently collapsed — so its cards become visible; the toggle handler lives on
	// the section head.
	cy.get("#user-settings_tab [data-fieldname='passkeys_section'] .section-head", {
		timeout: 20000,
	}).then(($head) => {
		if ($head.hasClass("collapsed")) {
			cy.wrap($head).click();
		}
	});
};

const own_passkey_root = () => cy.get(".passkey-cards-root:visible", { timeout: 20000 }).last();

chromium_only("passkey management — User form", () => {
	describe("cards", () => {
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

	describe("sudo-gated delete", () => {
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
});
