// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// First-factor retry recovery in one login-page lifetime. Automatic re-arms are
// bounded, but a later user click can always replace a state the client watched
// fail before opening WebAuthn.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login retry recovery", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.clear_guest_ceremony_rate_limit();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	beforeEach(() => {
		cy.login(USER, PW());
		cy.setup_passkey_settings();
		cy.clear_guest_ceremony_rate_limit();
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("fails twice, then succeeds with a valid passkey without reloading the login page", () => {
		let beginCalls = 0;
		let loginLoads = 0;
		const pageToken = {};
		cy.intercept("POST", "**/passkeys.passkey.begin_login", (req) => {
			beginCalls += 1;
		}).as("begin");
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify");
		cy.stub_post_login_shell();
		cy.visit_login_without_conditional({
			onBeforeLoad(win) {
				loginLoads += 1;
				win.__passkey_retry_page_token = pageToken;
				const credentials = win.navigator && win.navigator.credentials;
				if (!credentials || !credentials.get) return;
				const realGet = credentials.get.bind(credentials);
				win.__passkey_modal_get_calls = 0;
				Object.defineProperty(credentials, "get", {
					configurable: true,
					value(options) {
						if (options && options.mediation === "conditional") {
							return new Promise((resolve, reject) => {
								void resolve;
								if (options.signal) {
									options.signal.addEventListener("abort", () => {
										reject(new win.DOMException("aborted", "AbortError"));
									}, { once: true });
								}
							});
						}
						win.__passkey_modal_get_calls += 1;
						if (win.__passkey_modal_get_calls <= 2) {
							return Promise.reject(new win.DOMException("missing passkey", "NotAllowedError"));
						}
						return realGet(options);
					},
				});
			},
		});
		cy.wait("@begin").its("response.statusCode").should("be.within", 200, 299);

		cy.get("#passkey-login-btn").click();
		cy.window().its("__passkey_modal_get_calls").should("eq", 1);
		cy.get("#passkey-login-status").should("contain", "No passkey was used");
		cy.wait("@begin").its("response.statusCode").should("be.within", 200, 299);

		cy.get("#passkey-login-btn").click();
		cy.window().its("__passkey_modal_get_calls").should("eq", 2);
		cy.get("#passkey-login-status").should("contain", "No passkey was used");
		cy.window().should((win) => {
			expect(win.__passkey_retry_page_token, "same login-page window after two failures").to.equal(pageToken);
		});

		cy.get("#passkey-login-btn").click();
		cy.wait("@begin").its("response.statusCode").should("be.within", 200, 299);
		cy.wait("@verify", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
		cy.then(() => {
			expect(beginCalls, "initial begin, one auto re-arm, and one click recovery").to.eq(3);
			expect(loginLoads, "the login page loaded once across all three attempts").to.eq(1);
		});
	});

	it("shows unavailable after a failed pre-gesture re-begin and recovers on the next click", () => {
		let beginCalls = 0;
		cy.intercept("POST", "**/passkeys.passkey.begin_login", (req) => {
			beginCalls += 1;
			if (beginCalls === 2) {
				req.reply({ statusCode: 503, body: {} });
			}
		}).as("begin");
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify");
		cy.stub_post_login_shell();
		cy.visit_login_without_conditional();
		cy.wait("@begin").its("response.statusCode").should("be.within", 200, 299);
		cy.get("#passkey-login-btn").should("be.visible");
		cy.window().then((win) => {
			win.frappe._passkey_login._state.login.markSpent();
		});

		cy.get("#passkey-login-btn").click();
		cy.wait("@begin").its("response.statusCode").should("eq", 503);
		cy.get("#passkey-live-region").should("contain", "Passkeys aren't available right now");
		cy.get("#login_email").should("be.visible");

		cy.get("#passkey-login-btn").click();
		cy.wait("@begin").its("response.statusCode").should("be.within", 200, 299);
		cy.wait("@verify", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
		cy.then(() => {
			expect(beginCalls, "the later click retried begin").to.eq(3);
		});
	});
});
