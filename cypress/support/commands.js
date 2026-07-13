// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Cypress support commands for the passwordless-login specs. Two families:
//   1. CDP WebAuthn virtual-authenticator drivers (Chromium-only).
//   2. Frappe idiom (`cy.login`, `cy.call`) + higher-level app helpers that seed
//      a real resident credential through the committed registration ceremony,
//      so the login specs assert an end-to-end round trip with no key injection.
//
// Chromium-family browsers only. Specs guard with Cypress.isBrowser({family}).

// ---------------------------------------------------------------------------
// Low-level CDP bridge — undocumented but long-lived.
// ---------------------------------------------------------------------------
const cdp = (command, params = {}) =>
	Cypress.automation("remote:debugger:protocol", { command, params });

let current_authenticator_id = null;

// Platform passkey: discoverable ES256, UV supported + passing, presence auto.
const DEFAULT_AUTHENTICATOR_OPTIONS = {
	protocol: "ctap2",
	ctap2Version: "ctap2_1",
	transport: "internal",
	hasResidentKey: true,
	hasUserVerification: true,
	isUserVerified: true,
	automaticPresenceSimulation: true,
	defaultBackupEligibility: false,
	defaultBackupState: false,
};

// ---------------------------------------------------------------------------
// Virtual-authenticator lifecycle
// ---------------------------------------------------------------------------
Cypress.Commands.add("enable_virtual_authenticator", (options = {}) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.disable")
			.catch(() => {})
			.then(() => cdp("WebAuthn.enable", { enableUI: false }))
			.then(() =>
				cdp("WebAuthn.addVirtualAuthenticator", {
					options: { ...DEFAULT_AUTHENTICATOR_OPTIONS, ...options },
				})
			)
			.then(({ authenticatorId }) => {
				current_authenticator_id = authenticatorId;
				return authenticatorId;
			})
	)
);

Cypress.Commands.add("disable_virtual_authenticator", () =>
	cy.wrap(null, { log: false }).then(() => {
		const remove = current_authenticator_id
			? cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: current_authenticator_id })
			: Promise.resolve();
		return remove
			.catch(() => {})
			.then(() => {
				current_authenticator_id = null;
				return cdp("WebAuthn.disable").catch(() => {});
			});
	})
);

// ---------------------------------------------------------------------------
// Presence ("tap") + UV knobs
// ---------------------------------------------------------------------------
Cypress.Commands.add("hold_passkey_taps", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.setAutomaticPresenceSimulation", {
			authenticatorId: id || current_authenticator_id,
			enabled: false,
		})
	)
);

Cypress.Commands.add("simulate_passkey_tap", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.setAutomaticPresenceSimulation", {
			authenticatorId: id || current_authenticator_id,
			enabled: true,
		})
	)
);

Cypress.Commands.add("clear_virtual_credentials", (id) =>
	cy.wrap(null, { log: false }).then(() =>
		cdp("WebAuthn.clearCredentials", { authenticatorId: id || current_authenticator_id })
	)
);

// ---------------------------------------------------------------------------
// Frappe idiom (mirrors frappe/cypress/support/commands.js)
// ---------------------------------------------------------------------------
Cypress.Commands.add("login", (email, password, attempt = 0) => {
	if (!email) email = Cypress.config("testUser") || "Administrator";
	if (!password) password = Cypress.env("adminPassword") || "admin";
	return cy.request({
		url: "/api/method/login",
		method: "POST",
		body: { usr: email, pwd: password },
		failOnStatusCode: false,
	}).then((res) => {
		if (res.status >= 500 && attempt < 2) {
			return cy.wait(250, { log: false }).then(() => cy.login(email, password, attempt + 1));
		}
		expect(res.status).to.be.within(200, 399);
		return res;
	});
});

const normalize_csrf = (token) => (token && token !== "None" ? token : null);

const csrf_from_html = (html) => {
	const match = String(html || "").match(/frappe\.csrf_token\s*=\s*"([^"]+)"/);
	return normalize_csrf(match && match[1]);
};

const csrf_for_call = () =>
	cy.window({ log: false }).then((win) => {
		const frappe = win && win.frappe;
		const token = normalize_csrf(frappe && (frappe.csrf_token || (frappe.boot && frappe.boot.csrf_token)));
		if (token) return token;
		return cy
			.request({
				url: "/desk",
				method: "GET",
				failOnStatusCode: false,
			})
			.then((page) => csrf_from_html(page.body));
	});

Cypress.Commands.add("call", (method, args) =>
	csrf_for_call()
		.then((csrf_token) => {
			const headers = { Accept: "application/json" };
			if (csrf_token) headers["X-Frappe-CSRF-Token"] = csrf_token;
			return cy.request({
				url: `/api/method/${method}`,
				method: "POST",
				body: args,
				headers,
			});
		})
		.then((res) => res.body)
);

// ---------------------------------------------------------------------------
// App helpers
// ---------------------------------------------------------------------------

// RP ID = the site host, expected origin = the site origin — both derived from
// the CI-injected baseUrl so the specs work on any site name (passkeys.localhost
// locally, test_site on CI). The RP ID must equal the origin host for the
// browser ceremony to succeed.
const site_origin = () => new URL(Cypress.config("baseUrl")).origin;
const site_host = () => new URL(Cypress.config("baseUrl")).hostname;

// Cypress can mis-wait on the Desk base redirect chain; navigate to a concrete
// route so the transition to the booted app shell always resolves and `cy.visit`
// can finish waiting on `load`.
Cypress.Commands.add("visit_desk", (user = "Administrator", options = {}) => {
	const deskUser = encodeURIComponent(String(user || "Administrator"));
	// The desk GET writes tabSessions; under CI's constrained MariaDB it can
	// transiently deadlock / lock-wait-timeout, which Frappe returns as HTTP 508.
	// Retry the visit on a transient non-2xx/network blip rather than failing a
	// before/after hook on the first hiccup.
	const opts = { retryOnNetworkFailure: true, retryOnStatusCodeFailure: true, ...options };
	return cy.visit(`/app/user/${deskUser}`, opts).window().its("frappe").should("exist");
});

// Login-page specs often configure site state while authenticated, then need to
// exercise the Guest login route. Clear only auth cookies so deliberate request
// state such as preferred_language survives.
Cypress.Commands.add("visit_login", (options = {}) => {
	return cy.getCookie("preferred_language", { log: false }).then((language) => {
		cy.clearCookies({ log: false });
		if (language && language.value) {
			cy.setCookie("preferred_language", language.value, { log: false });
		}
		return cy.visit("/login", options);
	});
});

const disable_conditional_mediation = (win) => {
	const PKC = win && win.PublicKeyCredential;
	if (!PKC) return;
	try {
		Object.defineProperty(PKC, "getClientCapabilities", {
			configurable: true,
			value() {
				return Promise.resolve({
					conditionalCreate: false,
					conditionalGet: false,
					userVerifyingPlatformAuthenticator: true,
					hybridTransport: true,
				});
			},
		});
	} catch (e) {
		/* ignore read-only browser statics */
	}
	try {
		Object.defineProperty(PKC, "isConditionalMediationAvailable", {
			configurable: true,
			value() {
				return Promise.resolve(false);
			},
		});
	} catch (e) {
		/* ignore read-only browser statics */
	}
};

Cypress.Commands.add("visit_login_without_conditional", (options = {}) => {
	const onBeforeLoad = options.onBeforeLoad;
	return cy.visit_login({
		...options,
		onBeforeLoad(win) {
			disable_conditional_mediation(win);
			if (onBeforeLoad) onBeforeLoad(win);
		},
	});
});

Cypress.Commands.add("assert_logged_user", (user) =>
	cy
		.request("/api/method/frappe.auth.get_logged_user")
		.its("body.message")
		.should("eq", user)
);

const request_body_params = (body) => {
	if (!body) return {};
	if (typeof body === "object") return body;
	const raw = String(body);
	try {
		return JSON.parse(raw);
	} catch (e) {
		/* not JSON */
	}
	try {
		return Object.fromEntries(new URLSearchParams(raw));
	} catch (e) {
		return {};
	}
};

Cypress.Commands.add("intercept_frappe_method", (method, alias, handler) =>
	cy.intercept("POST", "**", (req) => {
		const params = request_body_params(req.body);
		const urlMethod = String(req.url || "").match(/\/api\/method\/([^/?#]+)/);
		const requestMethod = params.cmd || (urlMethod && decodeURIComponent(urlMethod[1]));
		if (requestMethod !== method) return;
		req.alias = alias;
		if (handler) return handler(req, params);
	})
);

Cypress.Commands.add("stub_post_login_shell", () => {
	const page = "<!doctype html><html><body data-cypress-desk-navigation=\"stub\"></body></html>";
	cy.intercept("GET", "/desk*", {
		statusCode: 200,
		headers: { "content-type": "text/html; charset=utf-8" },
		body: page,
	}).as("desk_navigation");
	cy.intercept("GET", "/app*", {
		statusCode: 200,
		headers: { "content-type": "text/html; charset=utf-8" },
		body: page,
	}).as("app_navigation");
});

// Configure Passkey Settings for this test site.
Cypress.Commands.add("setup_passkey_settings", (opts = {}) =>
	cy.call("passkeys.tests.ui_test_helpers.configure_login", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: 1,
		passkey_as_second_factor: opts.second_factor ? 1 : 0,
	})
);

Cypress.Commands.add("disable_passkey_login", () =>
	cy.call("passkeys.tests.ui_test_helpers.configure_login", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: 0,
		passkey_as_second_factor: 0,
	})
);

Cypress.Commands.add("purge_server_passkeys", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.purge_passkeys", { user })
);

Cypress.Commands.add("clear_registration_rate_limit", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.clear_registration_rate_limit", { user })
);

Cypress.Commands.add("clear_password_failures", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.clear_password_failures", { user })
);

// --- second-factor scaffolding ------------------------------------
// Turn on core 2FA (the structural floor) + passkey_as_second_factor, pointed at
// this UI-test origin. `first_factor`/`otp_fallback` toggle the co-features.
Cypress.Commands.add("setup_second_factor", (opts = {}) =>
	cy.call("passkeys.tests.ui_test_helpers.configure_second_factor", {
		rp_id: site_host(),
		origin: site_origin(),
		login_with_passkey: opts.first_factor ? 1 : 0,
		allow_otp_fallback: opts.otp_fallback ? 1 : 0,
	})
);

Cypress.Commands.add("teardown_second_factor", () =>
	cy.call("passkeys.tests.ui_test_helpers.teardown_second_factor", {})
);

// A non-admin user with a known password (the passkey second factor is hard-
// exempt for Administrator).
Cypress.Commands.add("ensure_sf_user", (email, pwd) =>
	cy.call("passkeys.tests.ui_test_helpers.ensure_second_factor_user", { email, pwd })
);

// Cover the user with a core-2FA role (call AFTER registering the passkey).
Cypress.Commands.add("enroll_user_2fa", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.enroll_user_in_2fa", { user })
);

Cypress.Commands.add("delete_test_user", (email) =>
	cy.call("passkeys.tests.ui_test_helpers.delete_test_user", { email })
);

// Seed a real discoverable credential for `user`: log in over the password leg
// (which seeds a sudo window), then drive the committed registration ceremony
// from the page (virtual authenticator generates the ES256 key — no injection).
// Leaves a resident credential on the authenticator AND a server row, so the
// subsequent login specs are a true end-to-end round trip.
Cypress.Commands.add("register_passkey", (user, password, options = {}) => {
	return cy
		.clear_registration_rate_limit(user)
		.then(() => cy.login(user, password))
		.then(() => {
			if (options.surface === "portal") {
				return cy.visit("/passkeys");
			}
			return cy.visit_desk(user, { onBeforeLoad: disable_conditional_mediation });
		})
		.then(() => cy.window().its("frappe").should("exist"))
		.then(() =>
			cy.window().then((win) =>
				win.frappe
					.call("passkeys.api.registration.begin_registration", { flow: "explicit" })
					.then((r) => {
						const opts = r.message.options;
						// Parse the L3 JSON options → CredentialCreationOptions, add the
						// credProps extension exactly as the bundle does.
						const create_opts = win.PublicKeyCredential.parseCreationOptionsFromJSON(opts);
						create_opts.extensions = { ...(create_opts.extensions || {}), credProps: true };
						return win.navigator.credentials
							.create({ publicKey: create_opts })
							.catch((err) => {
								throw new Error(
									`navigator.credentials.create failed: ${err && err.name}: ${err && err.message}`
								);
							})
							.then((cred) =>
								win.frappe.call("passkeys.api.registration.verify_registration", {
									state_id: r.message.state_id,
									credential: JSON.stringify(cred.toJSON()),
								})
							);
					})
			)
		);
});

// ---------------------------------------------------------------------------
// Action-confirmation suite lifecycle (shared by the confirm.cy.js describes so
// each keeps its own reset of the virtual authenticator + server passkeys).
// ---------------------------------------------------------------------------
Cypress.Commands.add("confirm_setup", () => {
	const USER = "Administrator";
	const PW = () => Cypress.env("adminPassword") || "admin";
	cy.enable_virtual_authenticator();
	cy.login(USER, PW());
	cy.visit_desk(USER);
	cy.setup_passkey_settings();
	cy.purge_server_passkeys(USER);
	cy.register_passkey(USER, PW());
	cy.login(USER, PW());
});

Cypress.Commands.add("confirm_teardown", () => {
	const USER = "Administrator";
	const PW = () => Cypress.env("adminPassword") || "admin";
	cy.login(USER, PW());
	cy.visit_desk(USER);
	cy.purge_server_passkeys(USER);
	cy.disable_virtual_authenticator();
	cy.clearCookies();
});
