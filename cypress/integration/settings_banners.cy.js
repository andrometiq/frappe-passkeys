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
const DOCS = "https://andrometiq.github.io/frappe-passkeys/";

function activate_settings_tab(tab_fieldname, field_selector) {
	cy.get(`.form-tabs .nav-link[data-fieldname='${tab_fieldname}']`, { timeout: 20000 })
		.should("be.visible")
		.click();
	return cy.get(field_selector, { timeout: 20000 }).should("be.visible");
}

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
		activate_settings_tab("relying_party_tab", "[data-fieldname='passkey_rp_id']")
			.should("contain.text", "Changing the RP ID invalidates every existing passkey");
	});

	it("warns when change notifications are turned off while a mode is on", () => {
		cy.visit("/app/passkey-settings");
		activate_settings_tab("notifications_tab", "[data-fieldname='passkey_notify_on_change']");
		cy.get("[data-fieldname='passkey_notify_on_change'] input[type='checkbox']").uncheck({ force: true });
		cy.contains("removes the main safeguard against a hijacked session").should("exist");
	});

	it("opens each tab with a Learn more link to its section of the guide", () => {
		const anchors = {
			login_modes_tab: "login-modes",
			relying_party_tab: "relying-party",
			enrollment_tab: "enrollment",
			security_tab: "security",
			notifications_tab: "notifications",
		};
		cy.visit("/app/passkey-settings");
		cy.get(".form-dashboard", { timeout: 20000 }).should("exist");
		Object.entries(anchors).forEach(([tab, anchor]) => {
			activate_settings_tab(tab, `#passkey-settings-${tab} .form-section-description a`)
				.should("have.text", "Learn more")
				.and("have.attr", "href", `${DOCS}configuration.html#${anchor}`)
				.and("have.attr", "target", "_blank")
				.and("have.attr", "rel", "noopener noreferrer");
		});
	});

	it("with both login modes off, shows one info line that links the Quickstart", () => {
		cy.intercept_frappe_method(
			"passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_settings_context",
			"settingsContext"
		);
		cy.visit("/app/passkey-settings");
		cy.wait("@settingsContext");
		// The shipped default: a passkey is always required from System Managers.
		cy.window().then(win => win.cur_frm.set_value("passkey_enforce_privileged_always", 1));
		cy.get("[data-fieldname='login_with_passkey'] input[type='checkbox']").uncheck({ force: true });
		cy.get("[data-fieldname='passkey_as_second_factor'] input[type='checkbox']").uncheck({ force: true });
		cy.get(".passkey-settings-banner.alert-info")
			.should("have.length", 1)
			.and("have.text", "Passkeys are off. To turn them on, follow the Quickstart.")
			.find("a")
			.should("have.attr", "href", `${DOCS}quickstart.html`)
			.and("have.attr", "target", "_blank")
			.and("have.attr", "rel", "noopener noreferrer");
		cy.contains("Enrollment enforcement has no effect").should("not.exist");
	});

	it("shows a mode's own settings only while that mode is on, and folds Mobile Apps until used", () => {
		const control = fieldname => cy.get(`.frappe-control[data-fieldname='${fieldname}']`);
		const set = values => cy.window().then(win => Object.entries(values).forEach(([k, v]) => win.cur_frm.set_value(k, v)));
		cy.visit("/app/passkey-settings");
		cy.get(".form-dashboard", { timeout: 20000 }).should("exist");
		set({ passkey_as_second_factor: 0, login_with_passkey: 0 });
		control("passkey_2fa_allow_otp_fallback").should("have.class", "hide-control");
		control("passkey_allow_first_enrollment_on_external_login").should("have.class", "hide-control");
		set({ passkey_as_second_factor: 1, login_with_passkey: 1 });
		control("passkey_2fa_allow_otp_fallback").should("not.have.class", "hide-control");
		control("passkey_allow_first_enrollment_on_external_login").should("not.have.class", "hide-control");

		const mobileBody = () => cy.get(".form-section[data-fieldname='mobile_apps_section'] > .section-body");
		activate_settings_tab("relying_party_tab", "[data-fieldname='passkey_rp_id']");
		mobileBody().should("have.class", "hide");
		cy.window().then(win => {
			win.cur_frm.doc.passkey_ios_team_id = "ABCDE12345";
			win.cur_frm.refresh();
		});
		mobileBody().should("not.have.class", "hide");
	});

	it("raises a loud confirm when the RP ID is changed", () => {
		cy.visit("/app/passkey-settings");
		activate_settings_tab("relying_party_tab", "[data-fieldname='passkey_rp_id'] input");
		cy.window().then(win => win.cur_frm.set_value("passkey_origins", "https://changed.example.com"));
		cy.intercept_frappe_method("passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_rp_id_change_impact", "rpImpact");
		cy.get("[data-fieldname='passkey_rp_id'] input")
			.clear()
			.type("changed.example.com")
			.blur();
		cy.wait("@rpImpact").its("response.statusCode").should("eq", 200);
		// frappe.warn renders a modal with the invalidation consequence
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog").should("contain.text", "invalidates every existing passkey");
	});
});
