// passkey_common.js — shared WebAuthn L3 helpers for the passkeys app.
// Destination on core merge: frappe/public/js/frappe/passkey/ (frappe.ui.passkey.*).
//
// This module is deliberately framework-light and side-effect-free at load time so its
// pure logic (JSON shim, feature detection, error mapping, selector resolution, retry
// state machine, i18n merge) can be unit-tested under plain `node --test` WITHOUT a bench.
//
// Dual export (UMD-lite): CommonJS `module.exports` for node tests; browser global
// `frappe.passkeys_common` for the login/portal/desk bundles (loaded as its own
// web_include_js/app_include_js entry BEFORE any bundle that reads it).
//
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) {
		module.exports = api; // node unit tests
	}
	if (typeof window !== "undefined") {
		window.frappe = window.frappe || {};
		window.frappe.passkeys_common = api; // browser bundles
	}
})(typeof self !== "undefined" ? self : this, function () {
	"use strict";

	// ------------------------------------------------------------------ i18n
	// window.__ === frappe._ is defined by frappe-web.bundle.js, loaded before every
	// web_include_js entry on all three branches. Fall back to identity so the
	// pure logic is testable and never throws pre-boot.
	function t(str, replacements) {
		var g = typeof window !== "undefined" ? window : {};
		if (typeof g.__ === "function") {
			return g.__(str, replacements);
		}
		return str;
	}

	// Merge (never clobber) an app translation catalog into frappe._messages.
	// frappe._messages legitimately holds Web-Form strings on v15/v16 pages and the full
	// core catalog on develop — Object.assign MERGES.
	function mergeAppTranslations(frappeRef, catalog) {
		if (!frappeRef || !catalog) return;
		frappeRef._messages = frappeRef._messages || {};
		Object.assign(frappeRef._messages, catalog);
	}

	// ------------------------------------------------------------- base64url
	function b64urlToBytes(b64url) {
		var b64 = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
		var pad = b64.length % 4;
		if (pad) b64 += "====".slice(pad); // tolerate unpadded input (spike)
		var bin = (typeof atob === "function")
			? atob(b64)
			: Buffer.from(b64, "base64").toString("binary");
		var bytes = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
		return bytes;
	}

	function bytesToB64url(buf) {
		var bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
		var bin = "";
		for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
		var b64 = (typeof btoa === "function")
			? btoa(bin)
			: Buffer.from(bin, "binary").toString("base64");
		return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}

	// ---------------------------------------------------- L3 JSON shim (request)
	// Prefer the native WebAuthn L3 static (Chrome 119+/Safari 18+); polyfill elsewhere.
	// NB: hybrid/QR cross-device must never be broken — we NEVER inject
	// authenticatorAttachment and we preserve unknown transports verbatim.
	function parseRequestOptionsFromJSON(json, PKC) {
		var Cred = PKC || (typeof window !== "undefined" ? window.PublicKeyCredential : undefined);
		if (Cred && typeof Cred.parseRequestOptionsFromJSON === "function") {
			return Cred.parseRequestOptionsFromJSON(json);
		}
		var out = {
			challenge: b64urlToBytes(json.challenge),
			timeout: json.timeout,
			rpId: json.rpId,
			userVerification: json.userVerification,
			extensions: json.extensions,
		};
		if (Array.isArray(json.allowCredentials)) {
			out.allowCredentials = json.allowCredentials.map(function (c) {
				var d = { type: c.type || "public-key", id: b64urlToBytes(c.id) };
				if (c.transports) d.transports = c.transports; // keep 'hybrid' & unknowns
				return d;
			});
		} else {
			out.allowCredentials = [];
		}
		return out;
	}

	// Serialize a live PublicKeyCredential assertion to AuthenticationResponseJSON.
	// Native cred.toJSON() (L3) is exactly what the server expects; polyfill otherwise.
	function authAssertionToJSON(cred) {
		if (cred && typeof cred.toJSON === "function") {
			return cred.toJSON();
		}
		var r = cred.response;
		var out = {
			id: cred.id,
			rawId: bytesToB64url(cred.rawId),
			type: cred.type,
			clientExtensionResults:
				typeof cred.getClientExtensionResults === "function"
					? cred.getClientExtensionResults()
					: {},
			response: {
				clientDataJSON: bytesToB64url(r.clientDataJSON),
				authenticatorData: bytesToB64url(r.authenticatorData),
				signature: bytesToB64url(r.signature),
				userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null,
			},
		};
		if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
		return out;
	}

	// ---------------------------------------------------- feature detection
	// Layered, never a single signal (the iOS 26.2 isUVPAA regression class):
	//   window.PublicKeyCredential defined -> getClientCapabilities() (absent key = UNKNOWN,
	//   not false) -> legacy statics isConditionalMediationAvailable / isUVPAA.
	function detectCapabilities(env) {
		env = env || {};
		var win = env.window || (typeof window !== "undefined" ? window : {});
		var PKC = env.PublicKeyCredential || win.PublicKeyCredential;
		var result = {
			supported: false,
			conditionalMediation: null, // null = unknown
			uvpaa: null,
			hybrid: null,
		};
		if (!PKC) {
			return Promise.resolve(result);
		}
		result.supported = true;

		function legacyProbes() {
			var jobs = [];
			if (result.conditionalMediation === null &&
				typeof PKC.isConditionalMediationAvailable === "function") {
				jobs.push(
					Promise.resolve()
						.then(function () { return PKC.isConditionalMediationAvailable(); })
						.then(function (v) { result.conditionalMediation = !!v; })
						.catch(function () { /* leave unknown */ })
				);
			}
			if (result.uvpaa === null &&
				typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
				jobs.push(
					Promise.resolve()
						.then(function () { return PKC.isUserVerifyingPlatformAuthenticatorAvailable(); })
						.then(function (v) { result.uvpaa = !!v; })
						.catch(function () { /* leave unknown */ })
				);
			}
			return Promise.all(jobs).then(function () { return result; });
		}

		if (typeof PKC.getClientCapabilities === "function") {
			return Promise.resolve()
				.then(function () { return PKC.getClientCapabilities(); })
				.then(function (caps) {
					caps = caps || {};
					// absent key => leave as null (unknown), never coerce to false
					if ("conditionalGet" in caps) result.conditionalMediation = !!caps.conditionalGet;
					if ("userVerifyingPlatformAuthenticator" in caps) {
						result.uvpaa = !!caps.userVerifyingPlatformAuthenticator;
					}
					if ("hybridTransport" in caps) result.hybrid = !!caps.hybridTransport;
					return legacyProbes();
				})
				.catch(function () { return legacyProbes(); });
		}
		return legacyProbes();
	}

	// ------------------------------------------------------- error mapping
	// Map a browser DOMException from navigator.credentials.get/create to a fixed code.
	// Codes are the exhaustive rejection taxonomy.
	function mapDomException(err) {
		var name = err && (err.name || err.code);
		switch (name) {
			case "NotAllowedError":
				// user cancelled OR timed out — indistinguishable by design (privacy)
				return { code: "user_cancelled", messageKey: "Couldn't use a passkey — sign in another way." };
			case "AbortError":
				return { code: "user_cancelled", messageKey: "Passkey sign-in was cancelled." };
			case "InvalidStateError":
				// on GET this is unusual; on registration = already-registered
				return { code: "confirmation_failed", messageKey: "That passkey can't be used here." };
			case "SecurityError":
				return { code: "not_supported", messageKey: "Passkeys aren't available on this page." };
			case "NotSupportedError":
				return { code: "not_supported", messageKey: "Passkeys aren't supported on this device." };
			case "ConstraintError":
				return { code: "no_credentials", messageKey: "No usable passkey was found." };
			case "UnknownError":
				return { code: "confirmation_failed", messageKey: "Couldn't complete passkey sign-in." };
			default:
				return { code: "network", messageKey: "Couldn't reach the passkey service — try again." };
		}
	}

	// Map a server typed error (exc_type — the class name is the wire value) to a
	// client action. Clients match on exc_type ONLY, never on message text.
	function mapServerExcType(excType) {
		switch (excType) {
			case "CeremonyExpired":
				return "ceremony_expired"; // transparent re-begin + one fresh gesture
			case "UnknownCredential":
				return "unknown_credential"; // signalUnknownCredential + neutral copy
			case "UVSetupRequired":
				return "uv_setup_required"; // inline password step-up
			case "PasskeyConfirmationRequired":
				return "confirmation_required";
			case "PasskeyServedByCore":
				return "served_by_core";
			default:
				return "unknown"; // delegate to core's painter
		}
	}

	// -------------------------------------------------- selector resolution
	// Two DOM generations, one contract. Probe selectors that no-op
	// on drift: a miss returns null and callers skip the patch/button — never throw.
	function resolveIdentifierInput(doc) {
		if (!doc) return null;
		// develop login.html:21, v16 :13, v15 :9 — id is stable across generations
		return doc.querySelector("#login_email");
	}

	// Find the visible section's action group (the login page shows one <section> at a
	// time via login.route()); prefer .page-card-actions, then a provider button group,
	// then the form itself. Returns {mount, mode} or null.
	function resolveButtonMount(doc) {
		if (!doc) return null;
		var visibleSection = pickVisibleSection(doc);
		var scope = visibleSection || doc;
		var actions = scope.querySelector(".page-card-actions");
		if (actions) return { mount: actions, mode: "actions" };
		var providers = scope.querySelector(".social-login-buttons");
		if (providers) return { mount: providers, mode: "providers" };
		var form = scope.querySelector(".form-login");
		if (form) return { mount: form, mode: "form" };
		return null;
	}

	// The section currently shown by login.route() (others are display:none). We tolerate
	// environments (tests) without computed style by falling back to the first section.
	function pickVisibleSection(doc) {
		var sections = doc.querySelectorAll("section");
		if (!sections || !sections.length) return null;
		for (var i = 0; i < sections.length; i++) {
			var s = sections[i];
			if (isVisible(s)) return s;
		}
		return sections[0];
	}

	function isVisible(el) {
		if (!el) return false;
		// inline style check first (JSDOM/stub friendly); getComputedStyle when available
		if (el.style && (el.style.display === "none" || el.style.visibility === "hidden")) return false;
		var win = el.ownerDocument && el.ownerDocument.defaultView;
		if (win && typeof win.getComputedStyle === "function") {
			var cs = win.getComputedStyle(el);
			if (cs && (cs.display === "none" || cs.visibility === "hidden")) return false;
		}
		if (typeof el.offsetParent !== "undefined" && el.offsetParent === null &&
			el.style && el.style.position !== "fixed") {
			// offsetParent null often means detached/hidden; keep permissive for stubs
			// (only trust it when the browser populates it)
		}
		return true;
	}

	// ---------------------------------------------------- retry state machine
	// Pins the retry contract. An assertion is NEVER re-POSTed; retry always
	// means a NEW ceremony + a NEW get()/create(). Re-arm is bounded at one per
	// user-visible failure, never an automatic loop.
	function CeremonyState(opts) {
		opts = opts || {};
		this.stateId = opts.stateId || null;
		this.options = opts.options || null;
		this.beginAt = typeof opts.beginAt === "number" ? opts.beginAt : Date.now();
		this.ttlMs = typeof opts.ttlMs === "number" ? opts.ttlMs : 300000;
		this.rearmCount = 0;
		this.maxRearm = typeof opts.maxRearm === "number" ? opts.maxRearm : 1;
	}
	// Pre-modal freshness: before any MODAL get(), if the held state's
	// age >= TTL, re-begin FIRST then run the single get() — one gesture, not two failures.
	CeremonyState.prototype.needsPreModalRebegin = function (now) {
		now = typeof now === "number" ? now : Date.now();
		return this.stateId !== null && (now - this.beginAt) >= this.ttlMs;
	};
	CeremonyState.prototype.adopt = function (stateId, options, now) {
		this.stateId = stateId;
		this.options = options;
		this.beginAt = typeof now === "number" ? now : Date.now();
	};
	// Re-arm after a verify that consumed the state without success — returns true if a
	// re-arm is permitted (bounded), false once the cap is hit (back to password form).
	CeremonyState.prototype.canRearm = function () {
		return this.rearmCount < this.maxRearm;
	};
	CeremonyState.prototype.markRearm = function () {
		this.rearmCount += 1;
		return this.rearmCount;
	};
	CeremonyState.prototype.reset = function () {
		this.rearmCount = 0;
	};

	// ---------------------------------------------------------- a11y helpers
	var LIVE_REGION_ID = "passkey-live-region";
	function ensureLiveRegion(doc) {
		if (!doc) return null;
		var region = doc.getElementById(LIVE_REGION_ID);
		if (region) return region;
		region = doc.createElement("div");
		region.id = LIVE_REGION_ID;
		region.setAttribute("aria-live", "polite");
		region.setAttribute("aria-atomic", "true");
		region.setAttribute("role", "status");
		region.className = "passkey-sr-only";
		(doc.body || doc.documentElement).appendChild(region);
		return region;
	}
	function announce(doc, message) {
		var region = ensureLiveRegion(doc);
		if (region) region.textContent = message;
	}
	// Focus management: save the active element so it can be restored after the OS sheet
	// or a dialog closes. Returns a restore() closure.
	function captureFocus(doc) {
		var prev = doc && doc.activeElement;
		return function restore() {
			if (prev && typeof prev.focus === "function") {
				try { prev.focus(); } catch (e) { /* element gone */ }
			}
		};
	}

	// ------------------------------------------------------------ inline icons
	// App-shipped inline SVGs (lucide artwork — pencil, trash-2, key; lucide is
	// ISC-licensed) so the management glyphs render IDENTICALLY on every Frappe
	// version instead of depending on the host icon sprite. v15's timeless/espresso
	// sprites carry NO #icon-pencil / #icon-trash / #icon-key, so the <use> refs
	// resolved to nothing and the buttons rendered as blank squares (A2). Centralised
	// here (loaded first on desk / login / portal) so every bundle shares one copy.
	var ICON_PATHS = {
		pencil:
			'<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/>' +
			'<path d="m15 5 4 4"/>',
		trash:
			'<path d="M3 6h18"/>' +
			'<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>' +
			'<path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' +
			'<line x1="10" x2="10" y1="11" y2="17"/>' +
			'<line x1="14" x2="14" y1="11" y2="17"/>',
		key:
			'<path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/>' +
			'<path d="m21 2-9.6 9.6"/>' +
			'<circle cx="7.5" cy="15.5" r="5.5"/>',
	};

	// Build an inline SVG icon string. `name` is a key in ICON_PATHS; unknown ⇒ "".
	// Keeps the caller's classes (icon / icon-sm) so sizing + theming still apply, but
	// PINS fill/stroke inline: Frappe's `.icon` drives them from CSS variables that
	// flip per version (v15 fills, develop strokes), which would otherwise turn this
	// outline art into solid blobs on v15. stroke:currentColor keeps dark-mode parity.
	function iconSvg(name, className) {
		var path = ICON_PATHS[name];
		if (!path) return "";
		var cls = className ? ' class="' + className + '"' : "";
		return (
			"<svg" + cls + ' viewBox="0 0 24 24" focusable="false" aria-hidden="true" ' +
			'style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">' +
			path +
			"</svg>"
		);
	}

	// ============================================================ confirm
	// Action-confirmation ("passkey signing") primitive — the PURE protocol
	// engine. Zero window/document/navigator/frappe references so the whole
	// begin -> gesture -> verify -> grant flow (+ the 401 retry / fingerprint
	// echo, + concurrency dedupe) is unit-testable under node:test
	// with injected deps. The frappe.ui.Dialog UI + fetch/navigator wiring live
	// in passkey_confirm.js, which passes real deps here.

	// Wire constants — MUST mirror passkeys/session.py GRANT_HEADER/GRANT_KWARG.
	var GRANT_HEADER = "X-Passkey-Grant";
	var GRANT_KWARG = "_passkey_grant";

	// Method paths the confirm client calls (server whitelist names). Kept
	// here so the server phase can grep the exact strings.
	var CONFIRM_METHODS = {
		begin: "passkeys.confirm.begin_confirmation",
		verify: "passkeys.confirm.verify_confirmation",
		reauth: "passkeys.confirm.reauth_password",
	};

	// The 401 retry-contract exc_type (wire taxonomy) and the fixed,
	// exhaustive rejection codes consuming apps program against.
	var CONFIRM_EXC_TYPE = "PasskeyConfirmationRequired";
	var CONFIRM_CODES = {
		USER_CANCELLED: "user_cancelled",
		NOT_SUPPORTED: "not_supported",
		NO_CREDENTIALS: "no_credentials",
		CONFIRMATION_FAILED: "confirmation_failed",
		FALLBACK_UNAVAILABLE: "fallback_unavailable",
		NETWORK: "network",
	};

	// frappe wraps a whitelisted dict return as {message: <dict>}; typed-error
	// bodies put their structured keys at TOP LEVEL via frappe.local.response.
	// So SUCCESS payloads are unwrapped from `.message`; ERROR payloads
	// are read at top level (parseConfirmationRequired below).
	function unwrapMessage(body) {
		if (body && typeof body === "object" && "message" in body) return body.message;
		return body;
	}

	// Parse a 401 body into the retry contract, or null if it isn't one. Clients
	// match on exc_type ONLY. Echoes payload_fingerprint VERBATIM —
	// JS never computes a hash.
	function parseConfirmationRequired(body) {
		if (!body || typeof body !== "object") return null;
		if (body.exc_type !== CONFIRM_EXC_TYPE) return null;
		return {
			action: body.action || null,
			payloadFingerprint: body.payload_fingerprint || null,
			methods: Array.isArray(body.methods) ? body.methods.slice() : [],
		};
	}

	// The header a caller attaches to the protected call once it holds a grant.
	// Header is primary; the _passkey_grant kwarg is the server-side
	// fallback (session.py) — the client uses the header.
	function buildGrantHeaders(token) {
		var h = {};
		if (token) h[GRANT_HEADER] = token;
		return h;
	}

	// Stable local key for concurrency dedupe ONLY ("concurrent invocations
	// share one dialog"). NOT a security hash and NEVER sent to the server — the
	// payload hash is server-computed. Sorted keys for stability.
	function confirmSignature(action, params, payloadFingerprint) {
		if (payloadFingerprint) return "fp:" + action + ":" + payloadFingerprint;
		var p = params || {};
		var keys = Object.keys(p).sort();
		var parts = [];
		for (var i = 0; i < keys.length; i++) {
			var v = p[keys[i]];
			parts.push(keys[i] + "=" + (typeof v === "object" ? JSON.stringify(v) : String(v)));
		}
		return "pp:" + action + ":" + parts.join("&");
	}

	// Pull the grant token from a verify_confirmation / reauth_password success
	// body. Server returns {grant: "<token>"} (wrapped as {message:{grant}}).
	function extractGrant(body) {
		var m = unwrapMessage(body);
		if (m && typeof m === "object" && m.grant) return m.grant;
		if (body && typeof body === "object" && body.grant) return body.grant;
		return null;
	}

	// Available authentication methods for a confirmation, from a
	// begin_confirmation response (authoritative, per-user) or a 401 body
	// (policy hint). methods ⊆ ["passkey","password","sudo"].
	function confirmCapabilities(methods) {
		var m = Array.isArray(methods) ? methods : [];
		return {
			passkey: m.indexOf("passkey") !== -1,
			password: m.indexOf("password") !== -1,
			sudo: m.indexOf("sudo") !== -1,
		};
	}

	function ConfirmError(code, message) {
		this.code = code;
		this.message = message || code;
	}

	// The engine. deps (all injected — nothing browser-bound here):
	//   post(method, body, headers) -> Promise<{ok, status, body}>
	//   runGesture(optionsJSON)     -> Promise<assertionJSON>  (parse + get + toJSON)
	//   ui: {
	//     chooseMethod({action, canPasskey, canPassword}) -> Promise<"passkey"|"password">
	//                                                          (reject to cancel)
	//     collectPassword()  -> Promise<string>              (reject to cancel)
	//     announce(msg), busy(bool), done(ok), passwordError(msg), close()
	//   }
	//   translate (optional): (str) -> str
	//   now (optional): () -> ms
	function createConfirmEngine(deps) {
		deps = deps || {};
		var post = deps.post;
		var runGesture = deps.runGesture;
		var makeUI = deps.ui; // () -> ui controller, OR a controller object
		var tr = deps.translate || function (s) { return s; };
		var maxPasswordTries = typeof deps.maxPasswordTries === "number" ? deps.maxPasswordTries : 5;

		var inflight = {}; // signature -> Promise (dedupe identical concurrent)
		var chain = Promise.resolve(); // serialize distinct dialogs (never stack two)

		function reject(code, msg) {
			return Promise.reject(new ConfirmError(code, tr(msg || code)));
		}

		function ui() {
			return typeof makeUI === "function" ? makeUI() : makeUI;
		}

		function mapGestureError(err) {
			if (err && err.code && CODE_SET[err.code]) return err; // already typed
			var mapped = mapDomException(err);
			return new ConfirmError(mapped.code, tr(mapped.messageKey));
		}

		// One confirmation ceremony. input:
		//   {action, params}                 (frappe.passkeys.confirm)
		//   {action, payloadFingerprint, methods}  (retry after a 401)
		function ceremony(input) {
			var action = input.action;
			var beginBody = input.payloadFingerprint
				? { action: action, payload_hash: input.payloadFingerprint } // echo verbatim
				: { action: action, params: input.params || {} };

			return post(CONFIRM_METHODS.begin, beginBody, {}).then(function (res) {
				if (!res || !res.ok) {
					// begin itself failed: served-by-core / disabled / network
					var parsed = res && parseConfirmationRequired(res.body);
					if (res && res.status === 417) return reject(CONFIRM_CODES.NOT_SUPPORTED, "Passkey confirmation isn't available here.");
					if (parsed) return reject(CONFIRM_CODES.CONFIRMATION_FAILED, "Couldn't start confirmation.");
					return reject(CONFIRM_CODES.NETWORK, "Couldn't reach the confirmation service — try again.");
				}
				var begin = unwrapMessage(res.body) || {};
				var stateId = begin.state_id;
				var options = begin.options;
				var fingerprint = begin.payload_fingerprint || input.payloadFingerprint || null;
				// begin's per-user methods are authoritative; fall back to the
				// 401 policy hint only if begin omitted them.
				var caps = confirmCapabilities(
					Array.isArray(begin.methods) ? begin.methods : input.methods
				);
				if (!caps.passkey && !caps.password) {
					return reject(CONFIRM_CODES.FALLBACK_UNAVAILABLE,
						"This action needs a passkey, and none is available.");
				}
				var controller = ui();
				return Promise.resolve()
					.then(function () {
						if (!caps.passkey) return "password"; // open straight on the password tab
						return controller.chooseMethod({
							action: action,
							canPasskey: caps.passkey,
							canPassword: caps.password,
						});
					})
					.then(function (method) {
						if (method === "password") {
							return passwordLeg(controller, action, fingerprint);
						}
						return passkeyLeg(controller, stateId, options);
					})
					.then(function (grant) {
						controller.done(true);
						return grant;
					})
					.catch(function (err) {
						controller.done(false);
						throw err;
					});
			}, function () {
				return reject(CONFIRM_CODES.NETWORK, "Couldn't reach the confirmation service — try again.");
			});
		}

		function passkeyLeg(controller, stateId, options) {
			controller.busy(true);
			controller.announce(tr("Waiting for your passkey…"));
			return Promise.resolve()
				.then(function () { return runGesture(options); })
				.catch(function (err) { throw mapGestureError(err); })
				.then(function (assertion) {
					return post(CONFIRM_METHODS.verify, { state_id: stateId, credential: assertion }, {});
				})
				.then(function (res) {
					if (!res || !res.ok) {
						// An assertion is NEVER re-POSTed; failure = fresh ceremony.
						controller.announce(tr("That didn't work — please try again."));
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							tr("Couldn't confirm with your passkey."));
					}
					var grant = extractGrant(res.body);
					if (!grant) throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED, tr("Confirmation didn't complete."));
					return grant;
				});
		}

		function passwordLeg(controller, action, fingerprint) {
			var tries = 0;
			function attempt() {
				return controller.collectPassword().then(function (pwd) {
					tries += 1;
					var body = { pwd: pwd, action: action };
					if (fingerprint) body.payload_fingerprint = fingerprint;
					return post(CONFIRM_METHODS.reauth, body, {}).then(function (res) {
						if (res && res.ok) {
							var grant = extractGrant(res.body);
							if (grant) return grant;
						}
						if (tries >= maxPasswordTries) {
							throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED, tr("Too many attempts. Try again later."));
						}
						controller.passwordError(tr("That password wasn't right. Try again."));
						return attempt();
					});
				});
			}
			return attempt();
		}

		// Concurrency: identical signatures share one in-flight promise;
		// distinct confirmations serialize so two dialogs never stack.
		function run(input) {
			var sig = confirmSignature(input.action, input.params, input.payloadFingerprint);
			if (inflight[sig]) return inflight[sig];
			var p = chain.then(function () { return ceremony(input); });
			inflight[sig] = p;
			var clear = function () { if (inflight[sig] === p) delete inflight[sig]; };
			p.then(clear, clear);
			// keep the chain alive but swallow errors so one failure can't poison the queue
			chain = p.then(function () {}, function () {});
			return p;
		}

		// Public: low-level — run the ceremony, resolve to a grant token.
		function confirm(action, params) {
			return run({ action: action, params: params || {} });
		}

		// Public: high-level — call a protected method, catch the 401 contract,
		// run the confirmation, retry ONCE with the grant header.
		function call(method, args) {
			args = args || {};
			return post(method, args, {}).then(function (res) {
				if (res && res.ok) return unwrapMessage(res.body);
				var req = res && res.status === 401 && parseConfirmationRequired(res.body);
				if (!req) throw httpError(res);
				return run({
					action: req.action,
					payloadFingerprint: req.payloadFingerprint,
					methods: req.methods,
				}).then(function (grant) {
					return post(method, args, buildGrantHeaders(grant)).then(function (res2) {
						if (res2 && res2.ok) return unwrapMessage(res2.body);
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							tr("The action couldn't be confirmed."));
					});
				});
			}, function () {
				throw new ConfirmError(CONFIRM_CODES.NETWORK, tr("Couldn't reach the server — try again."));
			});
		}

		function httpError(res) {
			// `res` is a REAL HTTP response that isn't the 401 retry contract (417
			// served-by-core, other 4xx, or 5xx with a non-contract body). The server
			// was reached and refused — that is NOT a transport failure. A dropped
			// fetch (offline/DNS) rejects the promise and is mapped to `network` at the
			// call site below; distinguishing the two lets callers tell "offline" from
			// "the server said no". Stays inside the fixed taxonomy: a
			// reached-but-failed request is `confirmation_failed`, never `network`.
			void res;
			return new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
				tr("The action couldn't be confirmed — please try again."));
		}

		return { confirm: confirm, call: call, run: run, _inflight: inflight };
	}

	var CODE_SET = {};
	(function () {
		for (var k in CONFIRM_CODES) if (CONFIRM_CODES.hasOwnProperty(k)) CODE_SET[CONFIRM_CODES[k]] = true;
	})();

	return {
		t: t,
		mergeAppTranslations: mergeAppTranslations,
		b64urlToBytes: b64urlToBytes,
		bytesToB64url: bytesToB64url,
		parseRequestOptionsFromJSON: parseRequestOptionsFromJSON,
		authAssertionToJSON: authAssertionToJSON,
		detectCapabilities: detectCapabilities,
		mapDomException: mapDomException,
		mapServerExcType: mapServerExcType,
		resolveIdentifierInput: resolveIdentifierInput,
		resolveButtonMount: resolveButtonMount,
		pickVisibleSection: pickVisibleSection,
		CeremonyState: CeremonyState,
		ensureLiveRegion: ensureLiveRegion,
		announce: announce,
		captureFocus: captureFocus,
		iconSvg: iconSvg,
		LIVE_REGION_ID: LIVE_REGION_ID,
		// action-confirmation ("passkey signing")
		GRANT_HEADER: GRANT_HEADER,
		GRANT_KWARG: GRANT_KWARG,
		CONFIRM_METHODS: CONFIRM_METHODS,
		CONFIRM_EXC_TYPE: CONFIRM_EXC_TYPE,
		CONFIRM_CODES: CONFIRM_CODES,
		unwrapMessage: unwrapMessage,
		parseConfirmationRequired: parseConfirmationRequired,
		buildGrantHeaders: buildGrantHeaders,
		confirmSignature: confirmSignature,
		extractGrant: extractGrant,
		confirmCapabilities: confirmCapabilities,
		ConfirmError: ConfirmError,
		createConfirmEngine: createConfirmEngine,
	};
});
