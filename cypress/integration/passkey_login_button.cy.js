// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Explicit "Sign in with a passkey" button. The
// button is always shown when a passkey login mode is enabled + WebAuthn is
// detected; clicking it runs a modal get() (allowCredentials empty, discoverable)
// → verify_login → redirect. When all modes are off, begin_login answers
// `enabled:false` and the bundle removes itself → no button.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey explicit-button login", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.setup_passkey_settings(); // re-enable (the disabled-mode test turns it off)
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("shows an accessible button mounted as the first alternate method", () => {
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn")
			.should("be.visible")
			.and("have.text", "Sign in with a passkey")
			.and(($b) => {
				expect($b.attr("type"), "button type").to.eq("button");
			});
		// first alternate-method control on the card
		cy.get(".btn-login-option").first().should("have.id", "passkey-login-btn");
	});

	it("completes a passwordless session on click", () => {
		cy.stub_post_login_shell();
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_login");
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();
		cy.wait("@verify_login", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});

	it("shows the visible staged status: verifying → you're in", () => {
		cy.stub_post_login_shell();
		// Delay the server round-trip so the "Verifying…" progress beat is deterministically
		// observable before the redirect. The status element is app-owned and renders
		// identically on v15/v16/develop, so this assertion is version-agnostic.
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_staged", (req) => {
			req.continue((res) => { res.setDelay(700); });
		});
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();
		// Stage 2 — server round-trip: a progress-toned status appears on the page itself.
		cy.get("#passkey-login-status")
			.should("be.visible")
			.and("have.class", "passkey-status--progress")
			.and("contain", "Verifying");
		cy.wait("@verify_staged", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		// Stage 3 — the resolved "You're in" beat, then core's redirect.
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});

	it("a removed/stale passkey shows a distinct visible reason instead of nothing (A5)", () => {
		// The credential is still on the device, but the server no longer recognises it
		// → UnknownCredential 401.
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_unknown", (req) => {
			req.reply({
				statusCode: 401,
				headers: { "Content-Type": "application/json" },
				body: { exc_type: "UnknownCredential", exception: "UnknownCredential" },
			});
		});
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();
		cy.wait("@verify_unknown", { timeout: 20000 });
		// Distinct "removed" state on the app-owned element (version-agnostic), NOT the
		// generic failure copy and NOT silence.
		cy.get("#passkey-login-status")
			.should("be.visible")
			.and("have.class", "passkey-status--error")
			.and("contain", "may have been removed");
		// …and the normal login form is still usable — never a dead end.
		cy.get("#login_email").should("be.visible");
	});

	it("removes itself when every login mode is off", () => {
		cy.login(USER, PW());
		cy.disable_passkey_login();
		cy.visit_login_without_conditional();
		cy.get("#login_email").should("exist"); // page rendered
		cy.get("#passkey-login-btn").should("not.exist");
	});
});
