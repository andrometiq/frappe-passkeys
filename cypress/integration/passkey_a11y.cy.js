// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Accessibility contract. One polite live region for
// async outcomes; the injected button carries an accessible name; first-factor
// passkey login delegates to the browser's native WebAuthn sheet, so this spec
// asserts the native get() handoff and cancellation feedback rather than an app
// dialog.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login accessibility", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
		// Register leaves the user authenticated; log out so the guest /login page
		// (where the button mounts) renders reliably instead of redirecting to the
		// desk. Mirrors the degrade / no-webauthn specs' before hooks.
		cy.call("logout");
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("exposes a live region and an accessibly-named button", () => {
		cy.visit_login_without_conditional();
		cy.get("#passkey-live-region")
			.should("have.attr", "role", "status")
			.and("have.attr", "aria-live", "polite")
			.and("have.attr", "aria-atomic", "true")
			.and("have.class", "passkey-sr-only");
		cy.get("#passkey-login-btn")
			.should("have.text", "Sign in with a passkey")
			.and("have.attr", "type", "button");
	});

	it("announces native prompt cancellation and returns focus", () => {
		cy.visit_login_without_conditional({
			onBeforeLoad(win) {
				const creds = win.navigator && win.navigator.credentials;
				if (!creds || !creds.get) return;
				win.__passkey_get_calls = [];
				Object.defineProperty(creds, "get", {
					configurable: true,
					value(options) {
						win.__passkey_get_calls.push(options);
						return Promise.reject(new win.DOMException("cancelled", "NotAllowedError"));
					},
				});
			},
		});
		cy.get("#passkey-login-btn").focus().click();
		cy.window().should((win) => {
			const call = (win.__passkey_get_calls || [])[0];
			expect(call, "native get call").to.exist;
			expect(call.publicKey, "publicKey options").to.exist;
			expect(call.mediation, "explicit request has no conditional mediation").to.be.undefined;
		});
		// Cancel and timeout are both NotAllowedError (indistinguishable by design), so the
		// ceremony collapses to the honest "cancelled" state. The aria-live region carries
		// its copy — one source of truth feeding both the SR and visible surfaces.
		cy.get("#passkey-live-region").should("contain", "No passkey was used");
		// The app ships its OWN visible status element on EVERY Frappe version
		// (v15/v16/develop), so — unlike core's develop-only .login-error-banner — the
		// visible failure state is version-agnostic and always assertable.
		cy.get("#passkey-login-status")
			.should("be.visible")
			.and("have.class", "passkey-status--error")
			.and("contain", "No passkey was used");
		cy.get("#login_email").should("be.visible");
		cy.focused().should("have.id", "passkey-login-btn");
	});
});
