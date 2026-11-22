// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// When the server doesn't serve the app's files (/assets/passkeys/*), as on a deploy that didn't
// publish them, Passkey Settings must say what to do and refuse to save, never fail silently on
// Save. Blocks every app asset, then walks the happy path: tick Login with Passkey, click Save.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const MISSING = "didn't load in this browser";

function saved_login_with_passkey() {
	return cy
		.request("/api/method/frappe.client.get_single_value?doctype=Passkey%20Settings&field=login_with_passkey")
		.its("body.message");
}

// A cached bundle never reaches the network, so the 404 below would not apply to it.
function set_browser_cache(enabled) {
	return cy.wrap(
		Cypress.automation("remote:debugger:protocol", { command: "Network.setCacheDisabled", params: { cacheDisabled: !enabled } })
	);
}

chromium_only("passkey settings — the app's files are not served", () => {
	beforeEach(() => {
		cy.login(USER, PW());
		cy.wrap(Cypress.automation("remote:debugger:protocol", { command: "Network.enable", params: {} }));
		set_browser_cache(false);
	});

	afterEach(() => {
		set_browser_cache(true);
	});

	it("shows what to do and refuses Save instead of failing silently", () => {
		saved_login_with_passkey().then((before) => {
			cy.intercept("GET", "/assets/passkeys/**", { statusCode: 404, body: "" }).as("appAsset");
			cy.visit("/app/passkey-settings");
			cy.get(".form-message", { timeout: 20000 }).should("contain", MISSING).and("contain", "bench build --app passkeys");
			cy.window().its("frappe.passkeys_manage_common").should("not.exist");

			cy.get("input[data-fieldname='login_with_passkey']").then(($box) => {
				cy.wrap($box)[$box.prop("checked") ? "uncheck" : "check"]({ force: true });
			});
			cy.get(".page-head .primary-action").filter(":visible").first().click();
			cy.get(".modal.show .msgprint", { timeout: 20000 }).should("contain", MISSING);
			saved_login_with_passkey().should("eq", before);
		});
	});
});
