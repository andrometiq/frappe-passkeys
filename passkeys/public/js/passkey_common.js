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
	// web_include_js entry on all three branches (§5.6). Fall back to identity so the
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
	// core catalog on develop — Object.assign MERGES, spec §5.6.
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
	// authenticatorAttachment and we preserve unknown transports verbatim (§5.4).
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
	// Layered, never a single signal (the iOS 26.2 isUVPAA regression class, §5.2 step 1):
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
	// Codes are the exhaustive rejection taxonomy shared with §7.3.
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

	// Map a server typed error (exc_type — the class name is the wire value, §3) to a
	// client action. Clients match on exc_type ONLY, never on message text.
	function mapServerExcType(excType) {
		switch (excType) {
			case "CeremonyExpired":
				return "ceremony_expired"; // transparent re-begin + one fresh gesture
			case "UnknownCredential":
				return "unknown_credential"; // signalUnknownCredential + neutral copy
			case "UVSetupRequired":
				return "uv_setup_required"; // inline password step-up (§3.4)
			case "PasskeyConfirmationRequired":
				return "confirmation_required";
			case "PasskeyServedByCore":
				return "served_by_core";
			default:
				return "unknown"; // delegate to core's painter
		}
	}

	// -------------------------------------------------- selector resolution
	// Two DOM generations, one contract (§5.2 step 5, §5.3). Probe selectors that no-op
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
	// Pins the §5.2.10 retry contract. An assertion is NEVER re-POSTed; retry always
	// means a NEW ceremony + a NEW get()/create(). Re-arm is bounded at one per
	// user-visible failure, never an automatic loop.
	function CeremonyState(opts) {
		opts = opts || {};
		this.stateId = opts.stateId || null;
		this.options = opts.options || null;
		this.beginAt = typeof opts.beginAt === "number" ? opts.beginAt : Date.now();
		this.ttlMs = typeof opts.ttlMs === "number" ? opts.ttlMs : 300000; // L3 §15.1
		this.rearmCount = 0;
		this.maxRearm = typeof opts.maxRearm === "number" ? opts.maxRearm : 1;
	}
	// Pre-modal freshness (§5.2.10 case a): before any MODAL get(), if the held state's
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
	// or a dialog closes (§5.5). Returns a restore() closure.
	function captureFocus(doc) {
		var prev = doc && doc.activeElement;
		return function restore() {
			if (prev && typeof prev.focus === "function") {
				try { prev.focus(); } catch (e) { /* element gone */ }
			}
		};
	}

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
		LIVE_REGION_ID: LIVE_REGION_ID,
	};
});
