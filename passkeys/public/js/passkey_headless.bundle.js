// The documented, markup-free JS API for custom UIs (docs/custom-ui.md): login,
// registration, list, rename, remove, the passwordless-only switch and capability
// detection. The shipped desk and portal UIs register through it too. Publishes
// `frappe.passkeys.headless` (and `frappe.ui.passkey.headless`); node tests use the pure
// `createHeadless` factory. Loads after passkey_common and passkey_manage_common.
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) module.exports = api;
	if (typeof window !== "undefined") publishBrowser(api);

	// The browser instance: the shared transport and gestures from passkey_common.
	function publishBrowser(api) {
		var f = window.frappe || {};
		var C = f.passkeys_common;
		if (!C) return;
		var M = f.passkeys_manage_common; // absent on a login-only page
		var instance = api.createHeadless({
			common: C,
			post: C.post,
			getAssertion: C.getAssertion,
			createCredential: C.createCredential,
			capabilities: function () { return C.detectCapabilities({ window: window }); },
			// Looked up per call: the confirm engine (desk confirm bundle, portal bundle, or a
			// custom page's own) may be published after this bundle loads.
			getConfirm: function () { return f.passkeys && f.passkeys.confirm; },
			getCall: function () { return f.passkeys && f.passkeys.call; },
			manageMethods: M ? M.MANAGE_METHODS : {},
			signalCredentialState: function (data) {
				var boot = f.boot && f.boot.passkeys;
				if (M) M.signalCredentialState(window.PublicKeyCredential, data, boot && boot.rp_id);
			},
			translate: C.t,
		});

		f.passkeys = f.passkeys || {};
		if (!f.passkeys.headless) f.passkeys.headless = instance;
		f.ui = f.ui || {};
		f.ui.passkey = f.ui.passkey || {};
		if (!f.ui.passkey.headless) f.ui.passkey.headless = instance;
	}
})(typeof self !== "undefined" ? self : this, function () {
	"use strict";

	// First-factor login methods; the second factor stays the shipped login bundle's job.
	var LOGIN_METHODS = {
		begin_login: "passkeys.passkey.begin_login",
		verify_login: "passkeys.passkey.verify_login",
		complete_uv_setup: "passkeys.passkey.complete_uv_setup",
	};

	// The codes register / rename / remove reject with (Error.code).
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

	// deps: common (passkey_common), post, getAssertion, createCredential (the passkey_common
	// signatures), capabilities(), getConfirm() / getCall() (the confirm engine or null),
	// manageMethods (MANAGE_METHODS), signalCredentialState(data), translate.
	function createHeadless(deps) {
		var C = deps.common;
		var post = deps.post;
		var getAssertion = deps.getAssertion;
		var createCredential = deps.createCredential;
		var capabilities = deps.capabilities;
		var getConfirm = deps.getConfirm || function () { return null; };
		var getCall = deps.getCall || function () { return null; };
		var signalCredentialState = deps.signalCredentialState || function () {};
		var LM = LOGIN_METHODS;
		var MM = deps.manageMethods || {};
		var MANAGE_ACTION = "passkeys.manage";
		var tr = deps.translate || function (s) { return s; };

		function unwrap(body) { return C.unwrapMessage(body); }
		function networkFailure() {
			return { ok: false, reason: "network", kind: "network", status: 0, message: null, statusState: "failed" };
		}
		function err(code, msg) {
			var e = new Error(code);
			e.code = code;
			e.message = tr(msg || code);
			return e;
		}

		// ------------------------------------------------------------- login
		// {enabled, modes, stateId, options}; stateId/options only when the first factor is
		// on. Rejects only on a transport failure.
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

		// Resolves a structured result, never rejects (shapes: docs/custom-ui.md).
		function verifyLogin(stateId, assertion) {
			var payload = {
				state_id: stateId,
				credential: typeof assertion === "string" ? assertion : JSON.stringify(assertion),
			};
			return post(LM.verify_login, payload, {}).then(function (res) {
				var out = loginResult(res);
				if (out.kind === "uv_setup_required") out.setupId = res.body.setup_id || null;
				return out;
			}, networkFailure);
		}

		function loginResult(res) {
			var body = (res && res.body) || {};
			if (res && res.ok) return { ok: true, redirect: body.home_page || body.redirect_to || null, raw: body };
			var kind = C.mapServerExcType(body.exc_type);
			return {
				ok: false,
				reason: "server",
				kind: kind,
				status: res ? res.status : 0,
				message: C.serverMessages(body) || null,
				statusState: C.loginStatusForServerKind(kind),
			};
		}

		// begin -> get() (opts.mediation / opts.signal for autofill) -> verify.
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
			}, networkFailure);
		}

		// Finish the one-time UV repair verifyLogin reports as uv_setup_required, with the
		// password the custom UI collected. Resolves like verifyLogin.
		function completeUvSetup(setupId, password) {
			return post(LM.complete_uv_setup, { setup_id: setupId, pwd: password }, {})
				.then(loginResult, networkFailure);
		}

		// ------------------------------------------------------ registration
		// begin (on the 401 contract: confirm passkeys.manage, then begin once more) ->
		// create() -> verify. Resolves {name, label, signal}; rejects a REG_CODES error.
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
						return post(MM.verifyRegistration, body, {}).then(function (res) {
							if (!res || !res.ok) throw mapVerifyError(res);
							var data = unwrap(res.body) || {};
							try { signalCredentialState(data); } catch (e) { /* best effort */ }
							return data;
						});
					});
			});
		}

		function beginRegistration(flow, retried) {
			return post(MM.beginRegistration, { flow: flow }, {}).then(function (res) {
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
			if (e && e.code && REG_CODES[e.code]) return e;
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
		function listCredentials() {
			return post(MM.list, {}, {}).then(function (res) {
				if (!res || !res.ok) throw err("list_failed", "Couldn't load your passkeys.");
				return unwrap(res.body) || { credentials: [], passkey_only_login: 0 };
			});
		}

		function renameCredential(name, label) {
			return post(MM.rename, { name: name, label: label }, {}).then(function (res) {
				if (!res || !res.ok) throw err("rename_failed", C.serverMessages(res && res.body) || "Couldn't rename the passkey.");
				return unwrap(res.body) || {};
			});
		}

		// Sudo-gated through frappe.passkeys.call. Afterwards the signal data is re-read so
		// an empty final list is signalled too.
		function removeCredential(name) {
			var call = getCall();
			if (typeof call !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"Removing a passkey needs a confirmation engine. See docs/custom-ui.md."));
			}
			return call(MM.del, { name: name }).then(function (result) {
				return post(MM.getSignalData, {}, {}).then(function (res) {
					if (res && res.ok) {
						try { signalCredentialState(unwrap(res.body) || {}); } catch (e) { /* best effort */ }
					}
					return result;
				}, function () { return result; });
			});
		}

		// Needs a passkey grant (never a password), through frappe.passkeys.call.
		function setPasswordlessOnly(enabled) {
			var call = getCall();
			if (typeof call !== "function") {
				return Promise.reject(err("confirmation_unavailable",
					"Changing passwordless login needs a confirmation engine. See docs/custom-ui.md."));
			}
			return call(MM.setPasskeyOnly, { enabled: !!enabled });
		}

		// ----------------------------------------------------- confirm proxies
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
			detectCapabilities: capabilities,
			beginLogin: beginLogin,
			verifyLogin: verifyLogin,
			login: login,
			completeUvSetup: completeUvSetup,
			register: register,
			listCredentials: listCredentials,
			renameCredential: renameCredential,
			removeCredential: removeCredential,
			setPasswordlessOnly: setPasswordlessOnly,
			confirm: confirm,
			call: call,
			LOGIN_METHODS: LM,
			MANAGE_METHODS: MM,
			REG_CODES: REG_CODES,
		};
	}

	return { createHeadless: createHeadless, LOGIN_METHODS: LOGIN_METHODS, REG_CODES: REG_CODES };
});
