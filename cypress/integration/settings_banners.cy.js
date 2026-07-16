// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Passkey Settings form UX. The form paints the
// banner matrix (from the pure passkey_manage_common.settingsBanners) and puts the
// loud one-way-door confirm on the RP-ID field. The banner decisions are unit-
// tested in passkey_manage_common.test.js; this spec checks they surface on the
// real form.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey settings — banners + one-way-door dialog", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
	});

	beforeEach(() => {
		cy.login(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("shows the RP-ID one-way-door warning beside the field", () => {
		cy.visit("/app/passkey-settings");
		cy.get(".form-dashboard", { timeout: 20000 }).should("exist");
		cy.get("[data-fieldname='passkey_rp_id']", { timeout: 20000 })
			.should("contain.text", "changing the RP ID invalidates every enrolled passkey");
	});

	it("warns when change notifications are turned off while a mode is on", () => {
		cy.visit("/app/passkey-settings");
		cy.get("[data-fieldname='passkey_notify_on_change'] input[type='checkbox']", { timeout: 20000 })
			.uncheck({ force: true });
		cy.contains("removes the main safeguard against a hijacked session").should("exist");
	});

	it("shows the all-modes-off info banner when both login modes are disabled", () => {
		cy.visit("/app/passkey-settings");
		cy.get("[data-fieldname='login_with_passkey'] input[type='checkbox']").uncheck({ force: true });
		cy.get("[data-fieldname='passkey_as_second_factor'] input[type='checkbox']").uncheck({ force: true });
		cy.contains("Both passkey login modes are off").should("exist");
	});

	it("raises a loud confirm when the RP ID is changed", () => {
		cy.visit("/app/passkey-settings");
		cy.get("[data-fieldname='passkey_rp_id'] input", { timeout: 20000 })
			.clear()
			.type("changed.example.com")
			.blur();
		// frappe.warn renders a modal with the invalidation consequence
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog").should("contain.text", "invalidates every existing passkey");
	});
});
