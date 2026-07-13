// passkey_headless.bundle.js — the documented, markup-free ("headless") public JS API a
// custom UI calls to drive the WHOLE passkey lifecycle without any of the app's
// own DOM: first-factor login, registration (add), list, rename, remove, the
// passwordless-only switch, and capability detection. Destination on core merge:
// frappe/public/js/frappe/passkey/ (frappe.ui.passkey.*).
//
// This is the SINGLE ceremony orchestrator shared by the app's own barebones
// surfaces and by third-party custom UIs. The app's portal card engine
// (passkey_portal.bundle.js) is a caller of `register()` here, so a custom UI
// exercises the exact same, tested code path the shipped UI does.
//
// Everything protocol/state-machine-shaped already lives in the two PURE libs:
//   * frappe.passkeys_common (passkey_common.bundle.js)        — base64url, the L3 JSON
//     shim, capability detection, DOMException/typed-error mapping, and the
//     node-tested createConfirmEngine (the re-auth engine behind frappe.passkeys.
//     confirm / .call).
//   * frappe.passkeys_manage_common (passkey_manage_common.bundle.js) — MANAGE_METHODS,
//     the card view-models, provider lookup, and the nudge/enforcement decisions.
// This module is the THIN browser wiring (fetch + CSRF + navigator.credentials)
// that ties those pure pieces to the server whitelist. It carries no markup and
// ships no styling — a custom UI supplies its own DOM and reads the result.
//
// Dual export (UMD-lite, mirrors passkey_common.bundle.js): the pure `createHeadless`
// factory (all browser deps injected) is `module.exports`-ed for `node --test`;
// the browser side wires the real fetch/navigator deps and publishes a default
// instance at `frappe.passkeys.headless` (+ forward-compat `frappe.ui.passkey.
// headless`). Loaded as its own web_include_js/app_include_js entry AFTER
// passkey_common.bundle.js (required) and passkey_manage_common.bundle.js (required for the
// management calls; login + capability detection need only the former).
//
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) {
		module.exports = api; // node unit tests
	}
	if (typeof window !== "undefined") {
		publishBrowser(api);
	}

	// ------------------------------------------------------------ browser wiring
	// Build a default headless instance from the real fetch + navigator.credentials
	// deps and the pure libs' globals, then publish it. Self-gates: with
	// frappe.passkeys_common absent it publishes nothing (like every other bundle).
	function publishBrowser(api) {
		var win = window;
		var C = win.frappe && win.frappe.passkeys_common;
		if (!C) return; // pure lib missing — fail safe, publish nothing
		var M = win.frappe && win.frappe.passkeys_manage_common;

		function methodUrl(method) {
			return "/api/method/" + method;
		}
		function jsonHeaders(extra) {
			var h = { "Content-Type": "application/json", Accept: "application/json" };
			var f = win.frappe;
			var token = f && (f.csrf_token || (f.boot && f.boot.csrf_token) || (f.session && f.session.csrf_token));
			if (token && token !== "None") h["X-Frappe-CSRF-Token"] = token; // authed POSTs need CSRF; guests exempt
			if (extra) for (var k in extra) if (extra.hasOwnProperty(k)) h[k] = extra[k];
			return h;
		}
		// Raw fetch so the caller owns the 401 body (the sudo/confirm retry contract)
		// and any typed error. Resolves {ok, status, body} for ANY HTTP status;
		// rejects only on a transport-level failure (offline / DNS).
		function post(method, body, headers) {
			return fetch(methodUrl(method), {
				method: "POST",
				headers: jsonHeaders(headers),
				credentials: "same-origin",
				body: JSON.stringify(body || {}),
			}).then(function (resp) {
				return resp.json().catch(function () { return null; }).then(function (json) {
					return { ok: resp.ok, status: resp.status, body: json };
				});
			});
		}

		// Run a get() gesture: parse the L3 RequestOptionsJSON, call navigator.
		// credentials.get (modal by default; conditional/autofill when opts.mediation
		// is set), serialize the assertion to AuthenticationResponseJSON.
		function getAssertion(optionsJSON, opts) {
			opts = opts || {};
			if (!navigator.credentials || typeof navigator.credentials.get !== "function") {
				return rejectNamed("NotSupportedError", "not supported");
			}
			var publicKey = C.parseRequestOptionsFromJSON(optionsJSON, win.PublicKeyCredential);
			var req = { publicKey: publicKey };
			if (opts.mediation) req.mediation = opts.mediation;
			if (opts.signal) req.signal = opts.signal;
			return navigator.credentials.get(req).then(function (cred) {
				if (!cred) return rejectNamed("NotAllowedError", "no credential");
				return C.authAssertionToJSON(cred);
			});
		}

		// Run a create() gesture: parse the L3 CreationOptionsJSON, inject the
		// credProps extension (py_webauthn emits none, so the discoverable tri-state
		// stays Unknown without it — mirrors the desk/portal bundles), call
		// navigator.credentials.create, serialize to RegistrationResponseJSON.
		function createCredential(optionsJSON) {
			if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
				return rejectNamed("NotSupportedError", "not supported");
			}
			var options = parseCreationOptions(optionsJSON);
			options.extensions = Object.assign({}, options.extensions || {}, { credProps: true });
			return navigator.credentials.create({ publicKey: options }).then(function (cred) {
				if (!cred) return rejectNamed("NotAllowedError", "no credential");
				return cred.toJSON ? cred.toJSON() : C.authAssertionToJSON(cred);
			});
		}

		// Prefer the native WebAuthn L3 static; polyfill the base64url members
		// otherwise (challenge, user.id, excludeCredentials[].id).
		function parseCreationOptions(json) {
			var PKC = win.PublicKeyCredential;
			if (PKC && typeof PKC.parseCreationOptionsFromJSON === "function") {
				return PKC.parseCreationOptionsFromJSON(json);
			}
			var out = Object.assign({}, json);
			out.challenge = C.b64urlToBytes(json.challenge);
			if (json.user && json.user.id) {
				out.user = Object.assign({}, json.user, { id: C.b64urlToBytes(json.user.id) });
			}
			if (Array.isArray(json.excludeCredentials)) {
				out.excludeCredentials = json.excludeCredentials.map(function (c) {
					return { type: c.type || "public-key", id: C.b64urlToBytes(c.id), transports: c.transports };
				});
			}
			return out;
		}

		function rejectNamed(name, msg) {
			var e = new Error(msg || name);
			e.name = name;
			return Promise.reject(e);
		}

		var instance = api.createHeadless({
			common: C,
			post: post,
			getAssertion: getAssertion,
			createCredential: createCredential,
			capabilities: function () { return C.detectCapabilities({ window: win }); },
			// Resolved LAZILY at call time: the confirm engine is published by
			// passkey_confirm.bundle.js (desk) or passkey_portal.bundle.js (portal), which may
			// load after this module. On a bare custom page the integrator wires their
			// own (see docs/custom-ui.md); until then removeCredential / the sudo dance
			// reject with a clear confirmation_unavailable.
			getConfirm: function () { return win.frappe && win.frappe.passkeys && win.frappe.passkeys.confirm; },
			getCall: function () { return win.frappe && win.frappe.passkeys && win.frappe.passkeys.call; },
			// Lazy so the live MANAGE_METHODS is read even if the manage-common lib
			// loaded after this module on a custom page.
			manageMethods: function () {
				var m = win.frappe && win.frappe.passkeys_manage_common;
				return (m && m.MANAGE_METHODS) || (M && M.MANAGE_METHODS) || {};
			},
			manageAction: (M && M.MANAGE_ACTION) || "passkeys.manage",
			loginMethods: api.LOGIN_METHODS,
			translate: C.t,
		});

		var f = (win.frappe = win.frappe || {});
		f.passkeys = f.passkeys || {};
		if (!f.passkeys.headless) f.passkeys.headless = instance;
		// forward-compat with the core destination namespace
		f.ui = f.ui || {};
		f.ui.passkey = f.ui.passkey || {};
		if (!f.ui.passkey.headless) f.ui.passkey.headless = instance;
	}
})(typeof self !== "undefined" ? self : this, function () {
	"use strict";

	// Server whitelist method paths for the first-factor login ceremony. MUST
	// mirror passkeys/passkey.py (kept here so the server phase can grep the exact
	// strings, exactly like CONFIRM_METHODS in passkey_common.bundle.js). The richer
	// second-factor / uv-setup endpoints are the shipped login bundle's job; the
	// headless login() drives the first-factor discoverable ceremony only.
	var LOGIN_METHODS = {
		begin_login: "passkeys.passkey.begin_login",
		verify_login: "passkeys.passkey.verify_login",
		complete_uv_setup: "passkeys.passkey.complete_uv_setup",
	};

	// Fixed, exhaustive result/error codes a custom UI programs against. Login
	// resolves a structured result carrying one of these; registration / rename /
	// remove REJECT an Error whose `.code` is one of these.
	var REG_CODES = {
		already_registered: true,
		user_cancelled: true,
		not_supported: true,
		add_failed: true,
		add_expired: true,
		confirmation_unavailable: true,
		list_failed: true,
		rename_failed: true,
	};

	// The engine. All browser dependencies are injected so the whole
	// begin -> gesture -> verify lifecycle is unit-testable under node:test with no
	// bench and no jsdom. deps:
	//   common          — frappe.passkeys_common (the pure lib)
	//   post(m,b,h)     -> Promise<{ok,status,body}>
	//   getAssertion(optionsJSON, opts?) -> Promise<assertionJSON>   (parse+get+toJSON)
	//   createCredential(optionsJSON)    -> Promise<attestationJSON> (parse+create+toJSON)
	//   capabilities()  -> Promise<caps>
	//   getConfirm()    -> confirm fn | null   (frappe.passkeys.confirm, lazy)
	//   getCall()       -> call fn | null       (frappe.passkeys.call, lazy)
	//   manageMethods   — frappe.passkeys_manage_common.MANAGE_METHODS
	//   manageAction    — the sudo-gate action ("passkeys.manage")
	//   loginMethods    — LOGIN_METHODS (or an override)
	//   translate(str)  — optional i18n
	function createHeadless(deps) {
		deps = deps || {};
		var C = deps.common;
		var post = deps.post;
		var getAssertion = deps.getAssertion;
		var createCredential = deps.createCredential;
		var capabilities = deps.capabilities;
		var getConfirm = deps.getConfirm || function () { return null; };
		var getCall = deps.getCall || function () { return null; };
		var LM = deps.loginMethods || LOGIN_METHODS;
		// manageMethods may be an object OR a lazy getter (browser default), so a
		// management call resolves the live MANAGE_METHODS even if the manage-common
		// lib loaded after this module on a custom page.
		var _MM = deps.manageMethods || {};
		var MANAGE_ACTION = deps.manageAction || "passkeys.manage";
		var tr = deps.translate || function (s) { return s; };

		function MM() { return (typeof _MM === "function" ? _MM() : _MM) || {}; }
		function unwrap(body) { return C.unwrapMessage(body); }
		function err(code, msg) {
			var e = new Error(code);
			e.code = code;
			e.message = tr(msg || code);
			return e;
		}

		// -------------------------------------------------------- capability
		function detectCapabilities() {
			return capabilities();
		}

		// ------------------------------------------------------------- login
		// Fetch fresh discoverable-credential options. Resolves the normalized
		// config {enabled, modes, stateId, options}; stateId/options are present
		// only when the first-factor mode is on (begin_login is also the config
		// channel). Rejects only on a transport failure.
		function beginLogin() {
			return post(LM.begin_login, {}, {}).then(function (res) {
				if (!res || !res.ok) {
					return { enabled: false, modes: { first_factor: false, second_factor: false }, stateId: null, options: null };
				}
				var cfg = unwrap(res.body) || {};
				return {
					enabled: !!cfg.enabled,
					modes: cfg.modes || { first_factor: false, second_factor: false },
					stateId: cfg.state_id || null,
					options: cfg.options || null,
				};
			});
		}

		// Verify a discoverable assertion against a begun ceremony. Resolves a
		// STRUCTURED result (never throws on a server refusal) so a custom UI can
		// switch on it:
		//   { ok:true, redirect }                              — session minted
		//   { ok:false, reason:"server", kind, status, message, statusState, setupId? }
		//   { ok:false, reason:"network", ... }                — transport failure
		// `kind` is the mapServerExcType taxonomy; `statusState` maps to the shipped
		// LOGIN_STATES copy (loginStatusForServerKind) if the UI wants to reuse it.
		function verifyLogin(stateId, assertion) {
			var payload = {
				state_id: stateId,
				credential: typeof assertion === "string" ? assertion : JSON.stringify(assertion),
			};
			return post(LM.verify_login, payload, {}).then(function (res) {
				if (res && res.ok) {
					var body = res.body || {};
					return { ok: true, redirect: body.home_page || body.redirect_to || null, raw: body };
				}
				var b = (res && res.body) || {};
				var kind = C.mapServerExcType(b.exc_type);
				var out = {
					ok: false,
					reason: "server",
					kind: kind,
					status: res ? res.status : 0,
					message: C.serverMessages(b) || null,
					statusState: C.loginStatusForServerKind(kind),
				};
				if (kind === "uv_setup_required") out.setupId = b.setup_id || null;
				return out;
			}, function () {
				return { ok: false, reason: "network", kind: "network", status: 0, message: null, statusState: "failed" };
			});
		}

		// Batteries-included first-factor login: beginLogin -> getAssertion (modal by
		// default; pass {mediation:"conditional", signal} for autofill) -> verifyLogin.
		// A get() rejection maps through the DOMException taxonomy to a structured
		// gesture result (statusState reuses loginStatusForDomCode). Resolves the same
		// shape family as verifyLogin plus:
		//   { ok:false, reason:"disabled" }                    — mode off / unconfigured
		//   { ok:false, reason:"gesture", code, message, statusState }
		function login(opts) {
			opts = opts || {};
			return beginLogin().then(function (cfg) {
				if (!cfg.enabled || !cfg.modes || !cfg.modes.first_factor || !cfg.stateId || !cfg.options) {
					return { ok: false, reason: "disabled", statusState: "idle" };
				}
				return Promise.resolve()
					.then(function () { return getAssertion(cfg.options, opts); })
					.then(
						function (assertion) { return verifyLogin(cfg.stateId, assertion); },
						function (e) {
							var m = C.mapDomException(e);
							return {
								ok: false, reason: "gesture", code: m.code,
								message: tr(m.messageKey), statusState: C.loginStatusForDomCode(m.code),
							};
						}
					);
			});
		}

		// ------------------------------------------------------ registration
		// Add a passkey (explicit flow by default). Runs the sudo dance: begin; on
		// the 401 confirmation contract run frappe.passkeys.confirm(passkeys.manage)
		// then retry begin ONCE; then create() (credProps injected) and verify.
		// Resolves the verify payload {name, label, signal}; rejects an Error whose
		// `.code` is in REG_CODES (already_registered / user_cancelled / add_expired
		// / add_failed / not_supported / confirmation_unavailable).
		function register(opts) {
			opts = opts || {};
			var flow = opts.flow || "explicit";
			return beginRegistration(flow, false).then(function (begin) {
				return Promise.resolve()
					.then(function () { return createCredential(begin.options); })
					.catch(function (e) { throw mapCreateError(e); })
					.then(function (attestation) {
						var body = {
							state_id: begin.state_id,
							credential: typeof attestation === "string" ? attestation : JSON.stringify(attestation),
						};
						if (opts.label) body.label = opts.label;
						return post(MM().verifyRegistration, body, {}).then(function (res) {
							if (!res || !res.ok) throw mapVerifyError(res);
							return unwrap(res.body) || {};
						});
					});
			});
		}

		function beginRegistration(flow, retried) {
			return post(MM().beginRegistration, { flow: flow }, {}).then(function (res) {
				if (res && res.ok) return unwrap(res.body);
				var req = res && res.status === 401 && C.parseConfirmationRequired(res.body);
				if (req && !retried) {
					var confirm = getConfirm();
					if (typeof confirm !== "function") {
						throw err("confirmation_unavailable",
							"This needs a fresh confirmation, but no confirmation engine is configured. See docs/custom-ui.md.");
					}
					return confirm(MANAGE_ACTION).then(function () { return beginRegistration(flow, true); });
				}
				throw mapVerifyError(res);
			});
		}

		function mapCreateError(e) {
			if (e && e.code && REG_CODES[e.code]) return e; // already typed (e.g. confirmation_unavailable from begin)
			var name = e && (e.name || e.code);
			if (name === "InvalidStateError") return err("already_registered", "This device already has a passkey for this account.");
			if (name === "NotAllowedError" || name === "AbortError") return err("user_cancelled", "Passkey creation was cancelled.");
			if (name === "NotSupportedError" || name === "SecurityError") return err("not_supported", "This browser can't create passkeys.");
			return err("add_failed", "Couldn't add a passkey — please try again.");
		}
		function mapVerifyError(res) {
			var exc = res && res.body && res.body.exc_type;
			if (C.mapServerExcType(exc) === "ceremony_expired") return err("add_expired", "That took too long — please try again.");
			return err("add_failed", C.serverMessages(res && res.body) || "Couldn't add a passkey — please try again.");
		}

		// -------------------------------------------------------- management
		// List the caller's own credentials. Resolves the server payload
		// {credentials:[...], passkey_only_login}. A read — not sudo-gated.
		function listCredentials() {
			return post(MM().list, {}, {}).then(function (res) {
				if (!res || !res.ok) throw err("list_failed", "Couldn't load your passkeys.");
				return unwrap(res.body) || { credentials: [], passkey_only_login: 0 };
			});
		}

		// Rename a credential (display-only, no sudo). Resolves {name, label}.
		function renameCredential(name, label) {
			return post(MM().rename, { name: name, label: label }, {}).then(function (res) {
				if (!res || !res.ok) throw err("rename_failed", C.serverMessages(res && res.body) || "Couldn't rename the passkey.");
				return unwrap(res.body) || {};
			});
		}

		// Remove a credential. Sudo-gated: routed through frappe.passkeys.call, which
		// catches the 401 confirmation contract, runs the confirm ceremony, and
		// retries with the grant header. Resolves {deleted}; rejects the confirm
		// engine's typed error (e.g. user_cancelled, or the server's verbatim
		// last-passkey guard message).
		function removeCredential(name) {
			var call = getCall();
			if (typeof call !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"Removing a passkey needs a confirmation engine. See docs/custom-ui.md."));
			}
			return call(MM().del, { name: name });
		}

		// Toggle the caller's passwordless-only (passkey-only) login. Gated on a
		// passkey grant ONLY (never a password) — routed through frappe.passkeys.call.
		// Resolves {passkey_only_login}.
		function setPasswordlessOnly(enabled) {
			var call = getCall();
			if (typeof call !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"Changing passwordless login needs a confirmation engine. See docs/custom-ui.md."));
			}
			return call(MM().setPasskeyOnly, { enabled: !!enabled });
		}

		// ----------------------------------------------------- confirm proxies
		// Re-expose the action-confirmation ("passkey signing") engine so a custom UI
		// has the whole surface under one namespace. These delegate to the published
		// frappe.passkeys.confirm / .call (built from the node-tested
		// createConfirmEngine); they reject clearly when no engine is configured.
		function confirm(action, params) {
			var c = getConfirm();
			if (typeof c !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"No confirmation engine is configured. See docs/custom-ui.md."));
			}
			return c(action, params);
		}
		function call(method, args) {
			var c = getCall();
			if (typeof c !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"No confirmation engine is configured. See docs/custom-ui.md."));
			}
			return c(method, args);
		}

		return {
			detectCapabilities: detectCapabilities,
			beginLogin: beginLogin,
			verifyLogin: verifyLogin,
			login: login,
			register: register,
			listCredentials: listCredentials,
			renameCredential: renameCredential,
			removeCredential: removeCredential,
			setPasswordlessOnly: setPasswordlessOnly,
			confirm: confirm,
			call: call,
			LOGIN_METHODS: LM,
			MANAGE_METHODS: MM(),
			REG_CODES: REG_CODES,
		};
	}

	return { createHeadless: createHeadless, LOGIN_METHODS: LOGIN_METHODS, REG_CODES: REG_CODES };
});
