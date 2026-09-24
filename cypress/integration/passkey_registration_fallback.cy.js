// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Registration fallback coverage with a real Chromium virtual authenticator and
// the real begin/verify endpoints. The credential's native L3 toJSON method is
// disabled so the committed bundles must serialize the attestation themselves.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const CRED_COUNT = "passkeys.tests.ui_test_helpers.credential_count";
const CONFIGURE_NUDGE = "passkeys.tests.ui_test_helpers.configure_nudge";
const SEED_NUDGE = "passkeys.tests.ui_test_helpers.seed_nudge_state";

const unwrap = (response) =>
	response && response.message !== undefined ? response.message : response;

function install_registration_fallback(win, conditionalAsExplicit = false) {
	const credentialPrototype = win.PublicKeyCredential && win.PublicKeyCredential.prototype;
	expect(Boolean(credentialPrototype), "PublicKeyCredential prototype exists").to.eq(true);
	win.__passkey_to_json_descriptor = Object.getOwnPropertyDescriptor(
		credentialPrototype,
		"toJSON"
	);
	Object.defineProperty(credentialPrototype, "toJSON", {
		configurable: true,
		value: undefined,
	});

	const credentials = win.navigator.credentials;
	const nativeCreate = credentials.create.bind(credentials);
	win.__passkey_create_descriptor = Object.getOwnPropertyDescriptor(credentials, "create");
	win.__passkey_create_calls = [];
	Object.defineProperty(credentials, "create", {
		configurable: true,
		value(options) {
			win.__passkey_create_calls.push(options);
			const request =
				conditionalAsExplicit && options && options.mediation === "conditional"
					? { publicKey: options.publicKey }
					: options;
			return nativeCreate(request).then((credential) => {
				win.__passkey_created_to_json_type = typeof credential.toJSON;
				return credential;
			});
		},
	});
}

function restore_registration_fallback(win) {
	const credentialPrototype = win.PublicKeyCredential && win.PublicKeyCredential.prototype;
	if (win.__passkey_to_json_descriptor) {
		Object.defineProperty(
			credentialPrototype,
			"toJSON",
			win.__passkey_to_json_descriptor
		);
	} else {
		delete credentialPrototype.toJSON;
	}
	if (win.__passkey_create_descriptor) {
		Object.defineProperty(
			win.navigator.credentials,
			"create",
			win.__passkey_create_descriptor
		);
	} else {
		delete win.navigator.credentials.create;
	}
}

function assert_registration_payload(body) {
	const credential = JSON.parse(body.credential);
	expect(credential.id, "credential id").to.be.a("string").and.not.be.empty;
	expect(credential.rawId, "raw credential id").to.be.a("string").and.not.be.empty;
	expect(credential.type).to.eq("public-key");
	expect(credential.clientExtensionResults).to.be.an("object");
	expect(credential.response.clientDataJSON, "client data").to.be.a("string").and.not.be.empty;
	expect(credential.response.attestationObject, "attestation object")
		.to.be.a("string")
		.and.not.be.empty;
	expect(credential.response).not.to.have.property("authenticatorData");
	expect(credential.response).not.to.have.property("signature");
	expect(credential.response).not.to.have.property("userHandle");
}

chromium_only("registration serialization fallback", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.call(CONFIGURE_NUDGE, {
			max_prompts: 3,
			cooldown_days: 30,
			conditional_create: 1,
		});
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.clear_virtual_credentials();
		cy.clear_user_rate_limits(USER);
		cy.call(SEED_NUDGE, { declines: 0, last_shown: null, opt_out: 0 });
	});

	it("enrolls from the portal without native credential toJSON", () => {
		let verifyPayload;
		cy.intercept_frappe_method(
			"passkeys.api.registration.verify_registration",
			"verify_registration",
			(_request, body) => {
				verifyPayload = body;
				assert_registration_payload(body);
			}
		);
		cy.visit("/passkeys", {
			onBeforeLoad(win) {
				install_registration_fallback(win);
			},
		});
		cy.get("#passkey-portal-root .passkey-empty-cta", { timeout: 20000 }).click();
		cy.wait("@verify_registration", { timeout: 20000 })
			.its("response.statusCode")
			.should("be.within", 200, 299);
		cy.then(() => expect(verifyPayload, "verify request payload").to.exist);
		cy.get("#passkey-portal-root .passkey-card", { timeout: 20000 }).should(
			"have.length",
			1
		);
		cy.window().then((win) => {
			expect(win.__passkey_created_to_json_type).to.eq("undefined");
			restore_registration_fallback(win);
		});
		cy.call(CRED_COUNT, { user: USER }).then((response) => {
			expect(unwrap(response)).to.eq(1);
		});
	});

	it("verifies conditional create without native credential toJSON", function () {
		cy.intercept_frappe_method(
			"passkeys.api.registration.verify_registration",
			"verify_registration",
			(_request, body) => assert_registration_payload(body)
		);
		cy.login(USER, PW());
		cy.visit_desk(USER, {
			onBeforeLoad(win) {
				install_registration_fallback(win, true);
			},
		});
		cy.window()
			.then((win) => {
				const PKC = win.PublicKeyCredential;
				if (!PKC || typeof PKC.getClientCapabilities !== "function") return false;
				return Promise.resolve(PKC.getClientCapabilities())
					.then((capabilities) => !!(capabilities && capabilities.conditionalCreate))
					.catch(() => false);
			})
			.then((capable) => {
				if (!capable) this.skip();
			});
		cy.window().should((win) => {
			const conditional = (win.__passkey_create_calls || []).find(
				(options) => options && options.mediation === "conditional"
			);
			expect(conditional, "conditional create request").to.exist;
			expect(conditional.signal, "conditional abort signal").to.exist;
		});
		cy.wait("@verify_registration", { timeout: 20000 })
			.its("response.statusCode")
			.should("be.within", 200, 299);
		cy.window().then((win) => {
			expect(win.__passkey_created_to_json_type).to.eq("undefined");
			restore_registration_fallback(win);
		});
		cy.call(CRED_COUNT, { user: USER }).then((response) => {
			expect(unwrap(response)).to.eq(1);
		});
	});
});
