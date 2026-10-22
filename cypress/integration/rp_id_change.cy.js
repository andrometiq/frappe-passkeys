// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE

const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const LABEL = "Before address change";
const HELPERS = "passkeys.tests.ui_test_helpers";
const ROOT = "#passkey-portal-root";

describe("passkeys after an RP ID change", () => {
	let credential_name;
	let original_rp;

	before(() => {
		const site = new URL(Cypress.config("baseUrl"));
		original_rp = site.hostname;
		cy.login(USER, PW());
		cy.setup_passkey_settings();
		cy.clear_user_rate_limits(USER);
		cy.clear_password_failures(USER);
		cy.purge_server_passkeys(USER);
		cy.call("passkeys.tests.fake_webauthn.enroll", {
			user: USER,
			seed: "rp-id-change",
			rp_id: original_rp,
			origin: site.origin,
			label: LABEL,
		}).then(({ message }) => {
			credential_name = message.name;
		});
	});

	after(() => {
		cy.login(USER, PW());
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.clearCookies();
	});

	it("greys the old card and removes it after password sudo confirmation", () => {
		cy.login(USER, PW());
		cy.intercept_frappe_method("passkeys.api.credentials.list_credentials", "list");
		cy.visit("/passkeys");
		cy.wait("@list").its("response.statusCode").should("eq", 200);
		cy.get(`${ROOT} .passkey-card`)
			.should("have.length", 1)
			.and("not.have.class", "passkey-card-stale")
			.and("contain.text", LABEL);

		// Keep the sudo flow in the browser's cookie channel, including its setup.
		cy.window().then((win) =>
			win.frappe.passkeys_common.post(`${HELPERS}.configure_login`, {
				rp_id: "changed.example.invalid",
				origin: "https://changed.example.invalid",
			})
		).its("status").should("eq", 200);
		cy.visit("/passkeys");
		cy.wait("@list").then(({ response }) => {
			expect(response.statusCode).to.eq(200);
			expect(response.body.message.site_rp_id).to.eq("changed.example.invalid");
			expect(response.body.message.credentials).to.have.length(1);
			expect(response.body.message.credentials[0]).to.include({
				name: credential_name, stale: true, usable: false,
			});
		});
		cy.get(`${ROOT} .passkey-card`)
			.should("have.class", "passkey-card-stale")
			.and("contain.text", `Made for ${original_rp}, doesn't work on this site`);
		cy.window().then((win) =>
			win.frappe.passkeys_common.post(`${HELPERS}.clear_sudo_window`, {})
		).its("status").should("eq", 200);
		cy.intercept_frappe_method("passkeys.api.credentials.delete_credential", "remove");
		cy.intercept_frappe_method("passkeys.confirm.reauth_password", "reauth");
		cy.get(`${ROOT} .passkey-delete`).should("be.enabled").click();
		cy.get(".passkey-dialog:visible")
			.should("contain.text", `${LABEL} was made for another address and doesn't work on this site.`)
			.contains("button", "Remove passkey").click();
		cy.wait("@remove").its("response.statusCode").should("eq", 401);
		cy.get(`${ROOT} .passkey-card`).should("have.length", 1);
		cy.get("#passkey-portal-pw").should("be.visible").type(PW(), { log: false });
		cy.get(".passkey-dialog:visible").contains("button", /^Confirm$/).click();
		cy.wait("@reauth").its("response.statusCode").should("eq", 200);
		cy.wait("@remove").then(({ response }) => {
			expect(response.statusCode).to.eq(200);
			expect(response.body.message.deleted).to.eq(credential_name);
		});
		cy.wait("@list").then(({ response }) => {
			expect(response.statusCode).to.eq(200);
			expect(response.body.message.credentials).to.deep.eq([]);
		});
		cy.get(`${ROOT} .passkey-card`).should("not.exist");
		cy.get(`${ROOT} .no-result`).should("be.visible");
	});
});
