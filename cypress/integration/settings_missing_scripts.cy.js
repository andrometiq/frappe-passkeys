// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// When the server doesn't serve the app's files (/assets/passkeys/*), as on a deploy that didn't
// publish them, Passkey Settings must say what to do and refuse to turn passkeys on, never fail
// silently on Save; turning them off must still save. Blocks every app asset, then walks Save.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const MISSING = "didn't load in this browser";

// No explicit origin: the helper writes past validation, and a saved http:// origin off localhost
// would make every later save (turning passkeys off included) fail server-side validation.
function configure(login_with_passkey) {
	const base = new URL(Cypress.config("baseUrl"));
	return cy.call("passkeys.tests.ui_test_helpers.configure_login", {
		rp_id: base.hostname,
		origin: "",
		login_with_passkey,
		passkey_as_second_factor: 0,
	});
}

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

function open_settings_without_app_files() {
	cy.intercept("GET", "/assets/passkeys/**", { statusCode: 404, body: "" });
	cy.visit("/app/passkey-settings");
	cy.get(".form-message", { timeout: 20000 }).should("contain", MISSING).and("contain", "bench build --app passkeys");
	cy.window().its("frappe.passkeys_manage_common").should("not.exist");
}

function click_save() {
	cy.get(".page-head .primary-action").filter(":visible").first().click();
}

chromium_only("passkey settings — the app's files are not served", () => {
	beforeEach(() => {
		cy.login(USER, PW());
		cy.wrap(Cypress.automation("remote:debugger:protocol", { command: "Network.enable", params: {} }));
		set_browser_cache(false);
	});

	afterEach(() => {
		set_browser_cache(true);
		configure(0);
	});

	it("refuses to turn passkeys on, saying what to do, instead of failing silently", () => {
		configure(0);
		open_settings_without_app_files();
		cy.get("input[data-fieldname='login_with_passkey']").check({ force: true });
		click_save();
		cy.get(".modal.show .msgprint", { timeout: 20000 }).should("contain", MISSING);
		saved_login_with_passkey().should("eq", 0);
	});

	it("still lets the admin turn passkeys off", () => {
		configure(1);
		open_settings_without_app_files();
		cy.intercept("POST", "/api/method/frappe.desk.form.save.savedocs").as("save");
		cy.get("input[data-fieldname='login_with_passkey']").uncheck({ force: true });
		click_save();
		cy.wait("@save").its("response.statusCode").should("eq", 200);
		saved_login_with_passkey().should("eq", 0);
		cy.get(".modal.show .msgprint").should("not.exist");
	});
});
