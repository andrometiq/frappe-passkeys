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

// A cached window.frappe.csrf_token can lag the jar's session: cy.login (and any
// server-side session change) mints a new sid in the cy.request jar WITHOUT reloading
// the page, so window.frappe.csrf_token still holds the prior session's token and
// Frappe 400s the POST on the mismatch (the intermittent manage_cards_portal after()
// CSRFTokenError seen on CI). csrf_fresh re-reads the token from /desk on the SAME jar,
// so it matches the jar's CURRENT session deterministically; cy.call retries once on a
// CSRF reject (or a transient 5xx), killing the mismatch class for every call site.
const csrf_fresh = () =>
	cy
		.request({ url: "/desk", method: "GET", failOnStatusCode: false, log: false })
		.then((page) => csrf_from_html(page.body));

const post_method = (method, args, csrf_token) => {
	const headers = { Accept: "application/json" };
	if (csrf_token) headers["X-Frappe-CSRF-Token"] = csrf_token;
	return cy.request({
		url: `/api/method/${method}`,
		method: "POST",
		body: args,
		headers,
		failOnStatusCode: false,
	});
};

const is_csrf_reject = (res) => String(JSON.stringify(res.body || "")).indexOf("CSRFToken") !== -1;

Cypress.Commands.add("call", (method, args) =>
	csrf_for_call()
		.then((token) => post_method(method, args, token))
		.then((res) => {
			if (!is_csrf_reject(res) && res.status < 500) {
				expect(res.status, `cy.call(${method})`).to.be.within(200, 299);
				return res.body;
			}
			// Stale window token or transient 5xx: fetch a jar-matching token fresh and retry once.
			return csrf_fresh()
				.then((fresh) => post_method(method, args, fresh))
				.then((res2) => {
					expect(res2.status, `cy.call(${method}) after fresh-CSRF retry`).to.be.within(200, 299);
					return res2.body;
				});
		})
);

// End the current SERVER session. The logout endpoint is POST-only and, for an
// authenticated session, needs that session's CSRF token — a bare GET is refused
// (403) and silently leaves the session alive. Guest sessions carry no CSRF token,
// so the same POST is a harmless no-op there. Retry a transient 5xx — CI's
// constrained MariaDB occasionally 508s on the session-row delete — so the session
// is reliably invalidated. failOnStatusCode is off so an already-guest no-op or a
// post-retry blip never fails the caller.
Cypress.Commands.add("server_logout", (attempt = 0) =>
	csrf_for_call().then((csrf_token) => {
		const headers = { Accept: "application/json" };
		if (csrf_token) headers["X-Frappe-CSRF-Token"] = csrf_token;
		return cy
			.request({
				url: "/api/method/logout",
				method: "POST",
				headers,
				failOnStatusCode: false,
				log: false,
			})
			.then((res) => {
				if (res.status >= 500 && attempt < 2) {
					return cy.wait(250, { log: false }).then(() => cy.server_logout(attempt + 1));
				}
				return res;
			});
	})
);

// Wipe EVERY server-side session (tabSessions row + redis cache entry) on the
// test site — the server half of test isolation. Cypress testIsolation clears
// only the CLIENT jar; stacked cy.login calls (register_passkey's re-login)
// orphan server sessions no client-side logout can end, and /login redirects
// on the SERVER store, so one re-presented stale sid sends a login-page spec
// to the desk (the passkey_a11y CI failure). After the wipe every such sid is
// inert no matter which jar layer or straggler response re-presents it. The
// helper is flag-gated server-side (passkeys_deterministic_test_cookies, or
// developer_mode + allow_tests): on an unflagged site this fails LOUDLY here
// rather than letting specs flake downstream.
//
// CSRF is fetched FRESH via GET /desk on the same cy.request jar as the POST,
// never from the loaded page's window: the window token belongs to the page's
// ORIGINAL session, while the jar may meanwhile carry a DIFFERENT still-valid
// sid (the lazy jar-sync class this whole helper exists to neutralize), and
// Frappe 400s on the mismatch — observed on CI. The /desk fetch resolves
// whatever session the jar actually carries and returns ITS token (or the
// guest login page's "None" → no header), so token and session always agree.
// Retries: transient 5xx like server_logout above (the wipe touches
// tabSessions harder than the single-row delete that already 508s on CI's
// constrained MariaDB), plus ONE bounded 400 retry — a straggler response can
// flip the jar between the token fetch and the POST; refetching realigns.
// A non-retryable failure (e.g. the missing-flag 417) fails immediately, by name.
Cypress.Commands.add("clear_all_test_sessions", (attempt = 0) =>
	cy
		.request({ url: "/desk", method: "GET", failOnStatusCode: false, log: false })
		.then((page) => {
			const csrf_token = csrf_from_html(page.body);
			const headers = { Accept: "application/json" };
			if (csrf_token) headers["X-Frappe-CSRF-Token"] = csrf_token;
			return cy.request({
				url: "/api/method/passkeys.tests.ui_test_helpers.clear_all_test_sessions",
				method: "POST",
				headers,
				failOnStatusCode: false,
				log: false,
			});
		})
		.then((res) => {
			if ((res.status >= 500 || res.status === 400) && attempt < 2) {
				return cy
					.wait(250, { log: false })
					.then(() => cy.clear_all_test_sessions(attempt + 1));
			}
			expect(res.status, "clear_all_test_sessions status").to.eq(200);
			const message = res.body && res.body.message;
			expect(message && message.remaining, "server sessions remaining after wipe").to.eq(0);
			return message;
		})
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
		// Guarantee a GUEST *server session* before visiting /login. /login decides
		// its redirect against the SERVER session store (login.py: `if session.user
		// != "Guest"`), not cookie presence, while Cypress test isolation clears only
		// the CLIENT jar. Three layers, each covering a hole the others cannot:
		//   1. server_logout — ends the CURRENT session with its CSRF token; also the
		//      only layer that works on sites without the deterministic-test flag.
		//   2. clear_all_test_sessions — wipes EVERY server session (DB row + redis
		//      cache), including sessions ORPHANED by stacked cy.login calls
		//      (register_passkey's re-login) that no client-side logout can reach.
		//      Whatever sid a lazily-synced jar layer or straggler response then
		//      re-presents is dead, which makes the /desk-resurrect class
		//      (passkey_a11y on CI) structurally impossible rather than unlikely.
		//   3. the passkeys_deterministic_test_cookies after_request hook
		//      (passkeys/cookie_determinism.py) — strips in-flight stale sid
		//      re-seeds, covering the cookie-level race window (both directions;
		//      see sid_reseed_race.cy.js).
		// The trailing location assertion turns any residual leak into an immediate,
		// named failure at this choke point instead of a cryptic missing-element
		// timeout in whichever spec runs next.
		cy.server_logout();
		cy.clearCookies({ log: false });
		cy.clear_all_test_sessions();
		if (language && language.value) {
			cy.setCookie("preferred_language", language.value, { log: false });
		}
		cy.visit("/login", options);
		return cy.location("pathname", { log: false }).then((pathname) => {
			if (pathname !== "/login") {
				// A stale session leaked past the wipe — an in-flight straggler
				// re-seeded the store after it ran. The substrate fixes make
				// this vanishingly rare; when it fires anyway, heal ONCE: by
				// now the straggler has landed, so a second wipe reaches its
				// session, and the re-visit must then render the form. A
				// second leak fails the hard assertion below — this never
				// masks a real guest-redirect defect, which would fail both
				// visits identically.
				Cypress.log({
					name: "visit_login",
					message: "stale server session leaked; healing once (wipe + re-visit)",
				});
				cy.clearCookies({ log: false });
				cy.clear_all_test_sessions();
				cy.visit("/login", options);
			}
			return cy.location("pathname", { log: false }).should((healed) => {
				expect(
					healed,
					"visit_login must land on the guest login form — a stale server session leaked twice (see clear_all_test_sessions)"
				).to.eq("/login");
			});
		});
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

// Reset EVERY app-owned per-user throttle for a user (delete/rename/list, the
// confirm + reauth ceremonies, record_nudge, enforcement admin, …). Specs hit
// these repeatedly through the real API, so across a full suite + reruns the
// shared per-user budget fills and a late call 429s (a card never disappears, a
// nudge-record assertion times out). A spec's before()/beforeEach starts from a
// clean budget, immune to whichever endpoint the accumulation happens to trip.
// See ui_test_helpers.clear_user_rate_limits.
Cypress.Commands.add("clear_user_rate_limits", (user) =>
	cy.call("passkeys.tests.ui_test_helpers.clear_user_rate_limits", { user })
);

// Reset frappe's IP-keyed guest-ceremony throttles (begin_login 30/min,
// verify_login 10/min, get_app_translations 30/min). Every login spec visits
// /login from the shared runner IP, and our CI runs the whole suite in ONE pass
// on one IP — so across the contiguous login specs the 60s window can fill and a
// ceremony 429s ("You hit the rate limit"). Each login spec clears in before()
// so it starts from a clean IP budget. Must run while authed (the helper is
// System-Manager-gated); call it after the setup login.
Cypress.Commands.add("clear_guest_ceremony_rate_limit", () =>
	cy.call("passkeys.tests.ui_test_helpers.clear_guest_ceremony_rate_limit")
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

// A non-admin user with a known password for isolated authentication specs.
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
