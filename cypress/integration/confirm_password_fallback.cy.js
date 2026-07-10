// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 3 — password fallback (DESIGN-v1 §7.2). For an allow_password_fallback
// action with no usable passkey, the dialog offers a password tab;
// reauth_password{pwd, action, payload_fingerprint} mints a password-method grant
// that authorizes the retry. Wrong password retries in-dialog. A
// allow_password_fallback=False action offers no password door (fallback_unavailable).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const FALLBACK_USER = `passkey-confirm-fallback-${Date.now()}@example.com`;
const FALLBACK_PW = "passkey-confirm-fallback-password";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";
const PROBE_ACTION = "passkeys.tests.confirm_probe";
const PROBE_PK_ONLY = "passkeys.tests.ui_test_helpers.confirm_probe_passkey_only";

const ensure_desk_access = (user) =>
	cy.call("frappe.client.get", { doctype: "User", name: user }).then((body) => {
		const doc = body.message;
		const roles = doc.roles || [];
		if (!roles.some((row) => row.role === "System Manager")) {
			roles.push({ role: "System Manager" });
			return cy.call("frappe.client.save", { doc: { ...doc, roles } });
		}
		return null;
	});

chromium_only("passkey action-confirmation — password fallback", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.ensure_sf_user(FALLBACK_USER, FALLBACK_PW);
		ensure_desk_access(FALLBACK_USER);
		cy.purge_server_passkeys(FALLBACK_USER); // no passkey → the dialog leads with password
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(FALLBACK_USER);
		cy.delete_test_user(FALLBACK_USER);
		cy.clearCookies();
	});

	it("mints a password-method grant and authorizes the action", () => {
		cy.login(FALLBACK_USER, FALLBACK_PW);
		cy.visit_desk(FALLBACK_USER);
		cy.request("/api/method/frappe.auth.get_logged_user")
			.its("body.message")
			.should("eq", FALLBACK_USER);
		cy.window().its("frappe.session.user").should("eq", FALLBACK_USER);
		cy.intercept("POST", "**/api/method/passkeys.confirm.reauth_password").as("reauthPassword");
		cy.window().then((win) => {
			delete win.__passkey_confirm_call;
		});
		cy.window().then((win) => {
			win.__passkey_confirm_call = win.frappe.passkeys.call(PROBE, { token: "PF1" });
		});
		cy.get(".passkey-confirm").should("be.visible");
		cy.get(".passkey-confirm-passkey").should("not.exist");
		cy.get(".passkey-confirm-pw").clear().type(FALLBACK_PW, { delay: 0 }).should("have.value", FALLBACK_PW);
		cy.get(".passkey-confirm-pwgo").click();
		cy.wait("@reauthPassword").then(({ request, response }) => {
			expect(request.body.pwd).to.eq(FALLBACK_PW);
			expect(request.body.action).to.eq(PROBE_ACTION);
			expect(response.statusCode).to.eq(200);
		});
		cy.window().then((win) =>
			cy.wrap(win.__passkey_confirm_call, { timeout: 20000 }).then((message) => {
				expect(message.confirmed).to.eq(true);
				expect(message.token).to.eq("PF1");
			})
		);
	});

	it("offers no password door when the action forbids fallback", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(FALLBACK_USER);
		cy.login(FALLBACK_USER, FALLBACK_PW);
		cy.visit_desk(FALLBACK_USER);
		cy.window().then((win) => {
			const p = win.frappe.passkeys
				.call(PROBE_PK_ONLY, { token: "X" })
				.then(() => {
					throw new Error("expected rejection");
				})
				.catch((err) => err);
			return cy.wrap(p, { timeout: 20000 }).then((err) => {
				expect(err.code).to.eq("fallback_unavailable");
				cy.get(".passkey-confirm").should("not.exist");
			});
		});
	});
});
