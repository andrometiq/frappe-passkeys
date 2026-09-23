// passkey_common.bundle.js — shared WebAuthn L3 helpers, side-effect-free at load so
// `node --test` can exercise them without a bench. Exports CommonJS for node and
// `frappe.passkeys_common` in the browser; it must load BEFORE any bundle that reads it.
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

	// Merge, never clobber: frappe._messages already holds Web-Form strings on v15/v16 and
	// the full core catalog on develop.
	function mergeAppTranslations(frappeRef, catalog) {
		if (!frappeRef || !catalog) return;
		frappeRef._messages = frappeRef._messages || {};
		Object.assign(frappeRef._messages, catalog);
	}

	// Fetch this app's catalog and merge it (web pages on v15/v16 ship no app strings;
	// on develop also await core's catalog). Never rejects: English is the fallback.
	function loadAppTranslations() {
		var f = window.frappe || {};
		var noop = function () {};
		var core = f._translations_loaded && typeof f._translations_loaded.then === "function"
			? f._translations_loaded.catch(noop) : null;
		// base.html stamps <html lang> with the request language: English needs no catalog.
		var lang = typeof document !== "undefined" && document.documentElement && document.documentElement.lang;
		var app = lang === "en" ? null : fetch("/api/method/passkeys.passkey.get_app_translations", {
			method: "GET",
			cache: "no-store",
			headers: { Accept: "application/json" },
			credentials: "same-origin",
		})
			.then(function (r) { return r.ok ? r.json() : null; })
			.then(function (payload) {
				var catalog = payload && (payload.message || payload);
				if (catalog && typeof catalog === "object") mergeAppTranslations(window.frappe, catalog);
			})
			.catch(noop);
		return Promise.all([core, app]);
	}

	// ------------------------------------------------------------- base64url
	function b64urlToBytes(b64url) {
		var b64 = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
		var pad = b64.length % 4;
		if (pad) b64 += "====".slice(pad); // tolerate unpadded input
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

	// Serialize a live PublicKeyCredential attestation to RegistrationResponseJSON.
	function registrationResponseToJSON(cred) {
		if (cred && typeof cred.toJSON === "function") {
			return cred.toJSON();
		}
		var r = cred.response;
		var response = {
			clientDataJSON: bytesToB64url(r.clientDataJSON),
			attestationObject: bytesToB64url(r.attestationObject),
		};
		if (typeof r.getTransports === "function") response.transports = r.getTransports();
		var out = {
			id: cred.id,
			rawId: bytesToB64url(cred.rawId),
			type: cred.type,
			clientExtensionResults:
				typeof cred.getClientExtensionResults === "function"
					? cred.getClientExtensionResults()
					: {},
			response: response,
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
	// Map a get()/create() DOMException to the fixed rejection taxonomy.
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
	// A selector miss returns null and callers skip the patch — never throw.
	function resolveIdentifierInput(doc) {
		if (!doc) return null;
		// develop login.html:21, v16 :13, v15 :9 — id is stable across generations
		return doc.querySelector("#login_email");
	}

	// Mount point in the visible login section: .page-card-actions, else a provider
	// button group, else the form. Returns {mount, mode} or null.
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
	var PRE_MODAL_REBEGIN_MARGIN_MS = 30000;
	function CeremonyState(opts) {
		opts = opts || {};
		this.stateId = opts.stateId || null;
		this.options = opts.options || null;
		this.beginAt = typeof opts.beginAt === "number" ? opts.beginAt : Date.now();
		this.ttlMs = typeof opts.ttlMs === "number" ? opts.ttlMs : 300000;
		this.spent = opts.spent === true;
		this.rearmCount = 0;
		this.maxRearm = typeof opts.maxRearm === "number" ? opts.maxRearm : 1;
	}
	// Pre-modal liveness: before any MODAL get(), replace a spent state or one near expiry.
	CeremonyState.prototype.needsPreModalRebegin = function (now) {
		now = typeof now === "number" ? now : Date.now();
		var freshnessLimit = Math.max(0, this.ttlMs - PRE_MODAL_REBEGIN_MARGIN_MS);
		return this.spent || (this.stateId !== null && (now - this.beginAt) >= freshnessLimit);
	};
	CeremonyState.prototype.adopt = function (stateId, options, now) {
		this.stateId = stateId;
		this.options = options;
		this.beginAt = typeof now === "number" ? now : Date.now();
		this.spent = false;
		this.rearmCount = 0;
	};
	CeremonyState.prototype.markSpent = function (stateId) {
		if (typeof stateId !== "undefined" && stateId !== this.stateId) return false;
		this.spent = true;
		return true;
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
		this.spent = false;
	};

	// -------------------------------------------------- login status machine
	// The first-factor login's visible status. Each state has ONE copy string that feeds
	// both the on-page status element and the aria-live region, so sighted and
	// screen-reader users always get the same message. Copy is the English base (wrapped
	// in t() at render); every error names a way out. Tone: progress / success / error.
	var LOGIN_STATES = {
		idle: { text: "", tone: "idle", visible: false, terminal: false },
		waiting: { text: "Waiting for your device…", tone: "progress", visible: true, terminal: false },
		verifying: { text: "Verifying your signature…", tone: "progress", visible: true, terminal: false },
		verifying_slow: {
			text: "Still verifying — this can take a moment on a slow connection.",
			tone: "progress", visible: true, terminal: false,
		},
		success: { text: "You're in — taking you through…", tone: "success", visible: true, terminal: true },
		cancelled: {
			text: "No passkey was used — you can try again or sign in another way.",
			tone: "error", visible: true, terminal: true,
		},
		// Server UnknownCredential. The copy never asserts the account fact ("didn't work
		// here", not "isn't registered"): enumeration-safe.
		removed: {
			text: "That passkey didn't work here — it may have been removed. Sign in another way.",
			tone: "error", visible: true, terminal: true,
		},
		unsupported: {
			text: "This device can't use passkeys yet — sign in with your password instead.",
			tone: "error", visible: true, terminal: true,
		},
		failed: { text: "Couldn't use a passkey — sign in another way.", tone: "error", visible: true, terminal: true },
	};

	// Legal transitions; an out-of-order call stays put, so a late error can never
	// overwrite "You're in" during the redirect. verifying→waiting serves the
	// ceremony_expired re-arm.
	var LOGIN_TRANSITIONS = {
		idle: ["waiting", "verifying"],
		waiting: ["verifying", "cancelled", "removed", "unsupported", "failed", "idle"],
		verifying: ["verifying_slow", "waiting", "success", "cancelled", "removed", "unsupported", "failed", "idle"],
		verifying_slow: ["waiting", "success", "cancelled", "removed", "unsupported", "failed", "idle"],
		success: [], // terminal — the page is redirecting
		cancelled: ["idle", "waiting", "verifying"],
		removed: ["idle", "waiting", "verifying"],
		unsupported: ["idle", "waiting", "verifying"],
		failed: ["idle", "waiting", "verifying"],
	};

	function loginStatusView(stateName) {
		return LOGIN_STATES[stateName] || LOGIN_STATES.idle;
	}

	function LoginStatus(opts) {
		opts = opts || {};
		this.state = LOGIN_STATES[opts.state] ? opts.state : "idle";
		this.strict = opts.strict !== false; // guard transitions by default
	}
	LoginStatus.prototype.can = function (next) {
		if (next === this.state) return true; // re-entry is always a safe no-op
		var allowed = LOGIN_TRANSITIONS[this.state] || [];
		return allowed.indexOf(next) !== -1;
	};
	// Transition and return the view to render. Illegal or unknown target ⇒ stay put and
	// return the CURRENT view, so the caller always has something coherent to paint.
	LoginStatus.prototype.to = function (next) {
		if (LOGIN_STATES[next] && (!this.strict || this.can(next))) {
			this.state = next;
		}
		return loginStatusView(this.state);
	};
	LoginStatus.prototype.view = function () { return loginStatusView(this.state); };

	// Map a mapDomException() code to a login state. Browsers report cancel and timeout
	// as the same NotAllowedError (privacy), so both land on "cancelled".
	function loginStatusForDomCode(code) {
		switch (code) {
			case "not_supported":
				return "unsupported";
			case "user_cancelled":
				return "cancelled";
			case "no_credentials":
				return "cancelled"; // "no usable passkey" — same route out, honestly indistinct
			default:
				return "failed"; // network / confirmation_failed / unknown
		}
	}

	// Map a mapServerExcType() kind to a login state. unknown_credential gets its own
	// state; every other refusal collapses to "failed" (enumeration-safe).
	function loginStatusForServerKind(kind) {
		switch (kind) {
			case "unknown_credential":
				return "removed";
			default:
				return "failed";
		}
	}

	// ------------------------------------------------------- signal builders
	// Base64url credential id: cred.id already is one per spec; else encode rawId; else null.
	function credentialIdB64url(cred) {
		if (!cred) return null;
		if (typeof cred.id === "string" && cred.id) return cred.id;
		if (cred.rawId) {
			try { return bytesToB64url(cred.rawId); } catch (e) { return null; }
		}
		return null;
	}

	// True when an assertion carried a non-empty userHandle (present as a base64url string
	// in JSON, or an ArrayBuffer/typed array on a live credential).
	function assertionHasUserHandle(cred) {
		var r = cred && cred.response;
		if (!r) return false;
		var uh = r.userHandle;
		if (uh == null) return false;
		if (typeof uh === "string") return uh.length > 0;
		if (typeof uh.byteLength === "number") return uh.byteLength > 0;
		return true;
	}

	// signalUnknownCredential payload {rpId, credentialId} for the credential the server
	// just rejected.
	//
	// Guard: only signal when the assertion carried a userHandle. The server raises
	// UnknownCredential for BOTH "credential row not found" (safe to prune) AND "assertion
	// had no userHandle" (the credential may still be live). The two are indistinguishable
	// from exc_type alone, but a returned userHandle means we're in the row-not-found case,
	// so we never risk telling a provider to hide a valid passkey. Returns null to skip.
	function buildUnknownCredentialSignal(cred, rpId) {
		if (!rpId || !cred) return null;
		if (!assertionHasUserHandle(cred)) return null;
		var credentialId = credentialIdB64url(cred);
		if (!credentialId) return null;
		return { rpId: rpId, credentialId: credentialId };
	}

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

	// ------------------------------------------------------- version-native icons
	// Native-first icons: use the first candidate <symbol> present in the host sprite so
	// each Frappe version renders its own glyph:
	//   pencil : develop/v16 lucide → #icon-pencil ; v15 timeless → #icon-edit
	//   trash  : develop/v16 lucide → #icon-trash  ; v15 timeless → #icon-delete
	//   key    : develop/v16 lucide → #icon-key    ; v15 has NO key glyph → inline fallback
	// With no candidate present (v15's key, or a page whose sprite is absent or loads after
	// us) we fall back to the inline SVG below, so a button is never blank.
	var ICON_SYMBOLS = {
		pencil: ["icon-pencil", "icon-edit"],
		trash: ["icon-trash", "icon-delete"],
		key: ["icon-key"],
	};

	// App-shipped inline SVGs (lucide artwork — pencil, trash-2, key; lucide is ISC-licensed)
	// used ONLY as the fallback when the host sprite carries no matching symbol. fill/stroke
	// are PINNED inline here because Frappe's `.icon` drives them from CSS variables that flip
	// per version (v15 fills, develop strokes), which would otherwise turn this outline art
	// into solid blobs on v15. The native <use> branch deliberately does NOT pin them — the
	// version whose sprite we reference already styles its own icon correctly.
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

	// Icon markup for `name` (unknown ⇒ ""), keeping the caller's classes. The native <use>
	// form carries no inline fill/stroke; the fallback is the pinned inline SVG. `doc`
	// defaults to the global document; tests inject a stub.
	function iconSvg(name, className, doc) {
		var cls = className ? ' class="' + className + '"' : "";
		var d = doc || (typeof document !== "undefined" ? document : null);
		var candidates = ICON_SYMBOLS[name];
		if (d && candidates) {
			for (var i = 0; i < candidates.length; i++) {
				var id = candidates[i];
				if (d.getElementById(id)) {
					return "<svg" + cls + ' focusable="false" aria-hidden="true"><use href="#' + id + '"></use></svg>';
				}
			}
		}
		var path = ICON_PATHS[name];
		if (!path) return "";
		return (
			"<svg" + cls + ' viewBox="0 0 24 24" focusable="false" aria-hidden="true" ' +
			'style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">' +
			path +
			"</svg>"
		);
	}

	// ============================================================ confirm
	// The action-confirmation protocol engine: begin -> gesture -> verify -> grant, the 401
	// retry with fingerprint echo, and concurrency dedupe. No browser globals; the UI and
	// fetch/navigator wiring are injected (passkey_confirm.bundle.js, the portal bundle).

	// Wire constants — MUST mirror passkeys/session.py GRANT_HEADER/GRANT_KWARG.
	var GRANT_HEADER = "X-Passkey-Grant";
	var GRANT_KWARG = "_passkey_grant";

	// Method paths the confirm client calls (server whitelist names).
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

	// The text in a thrown error's `_server_messages` (a JSON string of JSON-encoded
	// {message,...} dicts), so a server refusal is shown verbatim. Null when absent.
	function serverMessages(body) {
		if (!body || typeof body !== "object" || !body._server_messages) return null;
		var arr;
		try {
			arr = typeof body._server_messages === "string"
				? JSON.parse(body._server_messages)
				: body._server_messages;
		} catch (e) {
			return null;
		}
		if (!Array.isArray(arr) || !arr.length) return null;
		var msgs = [];
		for (var i = 0; i < arr.length; i++) {
			var text = "";
			try {
				var o = typeof arr[i] === "string" ? JSON.parse(arr[i]) : arr[i];
				text = o && typeof o === "object" ? (o.message || "") : String(arr[i]);
			} catch (e) {
				text = String(arr[i]);
			}
			if (text) msgs.push(String(text));
		}
		return msgs.length ? msgs.join(" ") : null;
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
			actionLabel: typeof body.action_label === "string" ? body.action_label : null,
			parameterSummary: body.parameter_summary !== undefined ? body.parameter_summary : null,
		};
	}

	var CONFIRM_ACTION_LABELS = {
		"passkeys.manage": "Manage passkeys",
		"passkeys.set_passkey_only_login": "Change passkey-only login",
	};

	function confirmationActionContext(action, serverLabel, serverSummary) {
		var fromServer = typeof serverLabel === "string" && !!serverLabel.trim();
		var label = fromServer ? serverLabel.trim() : (CONFIRM_ACTION_LABELS[action] || humanizeAction(action));
		return {
			label: label || "Confirm action",
			labelFromServer: fromServer,
			summary: normalizeConfirmationSummary(serverSummary),
		};
	}

	function humanizeAction(action) {
		var tail = String(action || "").split(".").pop().replace(/[_-]+/g, " ").trim();
		if (!tail) return "";
		return tail.charAt(0).toUpperCase() + tail.slice(1);
	}

	// Server summaries are display data, never protocol inputs. Accept only bounded
	// primitive label/value pairs (or bounded strings); nested objects and markup are
	// discarded, and each DOM adapter escapes/text-renders the returned values.
	function normalizeConfirmationSummary(summary) {
		var rows = [];
		function primitive(v) {
			if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
				return String(v).slice(0, 240);
			}
			return null;
		}
		function add(label, value) {
			if (rows.length >= 6) return;
			var v = primitive(value);
			if (v === null || !v.trim()) return;
			var l = primitive(label);
			rows.push({ label: l && l.trim() ? l.slice(0, 80) : null, value: v });
		}
		if (Array.isArray(summary)) {
			summary.forEach(function (item) {
				if (item && typeof item === "object" && !Array.isArray(item)) {
					add(item.label || item.name || item.key, item.value !== undefined ? item.value : item.summary);
				} else add(null, item);
			});
		} else if (summary && typeof summary === "object") {
			Object.keys(summary).forEach(function (key) { add(key, summary[key]); });
		} else add(null, summary);
		return rows;
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
	//     collectPassword({action, actionLabel, parameterSummary}) -> Promise<string>
	//                                                          (reject to cancel)
	//     announce(msg), busy(bool), done(ok), passwordError(msg)
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
				// On call() retries the initial 401 came from the protected action
				// itself and carries its explicitly safe display metadata. Keep it
				// across a worker handoff where begin may know only the safe default.
				var actionLabel = input.actionLabel ||
					(typeof begin.action_label === "string" ? begin.action_label : null);
				var parameterSummary = input.parameterSummary !== undefined && input.parameterSummary !== null
					? input.parameterSummary : begin.parameter_summary;
				var displayContext = {
					action: action,
					actionLabel: actionLabel,
					parameterSummary: parameterSummary,
				};
				// begin's per-user methods are authoritative; fall back to the
				// 401 policy hint only if begin omitted them.
				var caps = confirmCapabilities(
					Array.isArray(begin.methods) ? begin.methods : input.methods
				);
				if (!caps.passkey && !caps.password) {
					// No way to re-authenticate (weak login, no password, no usable passkey):
					// say what to do instead.
					return reject(CONFIRM_CODES.FALLBACK_UNAVAILABLE,
						"This needs you to confirm it's you, but this sign-in can't be confirmed " +
						"with a passkey or password. Sign in again with your password or a passkey, then try again.");
				}
				var controller = ui();
				return Promise.resolve()
					.then(function () {
						if (!caps.passkey) return "password"; // open straight on the password tab
						return controller.chooseMethod({
							action: displayContext.action,
							actionLabel: displayContext.actionLabel,
							parameterSummary: displayContext.parameterSummary,
							canPasskey: caps.passkey,
							canPassword: caps.password,
						});
					})
					.then(function (method) {
						if (method === "password") {
							return passwordLeg(controller, action, fingerprint, displayContext);
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
						// An assertion is NEVER re-POSTed; failure = fresh ceremony. Surface
						// any server message; otherwise honest copy that points at the password.
						controller.announce(tr("That didn't work — please try again."));
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							serverMessages(res && res.body) ||
								tr("That passkey didn't confirm it's you. Try again, or use your password."));
					}
					var grant = extractGrant(res.body);
					if (!grant) throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED, tr("Confirmation didn't complete."));
					return grant;
				});
		}

		function passwordLeg(controller, action, fingerprint, displayContext) {
			var tries = 0;
			function attempt() {
				return controller.collectPassword(displayContext).then(function (pwd) {
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
					actionLabel: req.actionLabel,
					parameterSummary: req.parameterSummary,
				}).then(function (grant) {
					return post(method, args, buildGrantHeaders(grant)).then(function (res2) {
						if (res2 && res2.ok) return unwrapMessage(res2.body);
						// Confirmed, but the retry still failed: show the server's own refusal
						// (e.g. the last-passkey guard, which runs after the sudo gate).
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							serverMessages(res2 && res2.body) ||
								tr("We confirmed it's you, but the action still didn't go through — please try again."));
					});
				});
			}, function () {
				throw new ConfirmError(CONFIRM_CODES.NETWORK, tr("Couldn't reach the server — try again."));
			});
		}

		function httpError(res) {
			// A real HTTP response that isn't the 401 contract: the server was reached and
			// refused, so it is `confirmation_failed` (with the server's message when it sent
			// one), never `network`. A dropped fetch rejects and maps to `network` below.
			return new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
				serverMessages(res && res.body) ||
					tr("The action couldn't be confirmed — please try again."));
		}

		return { confirm: confirm, call: call, run: run, _inflight: inflight };
	}

	var CODE_SET = {};
	(function () {
		for (var k in CONFIRM_CODES) if (Object.prototype.hasOwnProperty.call(CONFIRM_CODES, k)) CODE_SET[CONFIRM_CODES[k]] = true;
	})();

	return {
		t: t,
		mergeAppTranslations: mergeAppTranslations,
		loadAppTranslations: loadAppTranslations,
		b64urlToBytes: b64urlToBytes,
		bytesToB64url: bytesToB64url,
		parseRequestOptionsFromJSON: parseRequestOptionsFromJSON,
		authAssertionToJSON: authAssertionToJSON,
		registrationResponseToJSON: registrationResponseToJSON,
		detectCapabilities: detectCapabilities,
		mapDomException: mapDomException,
		mapServerExcType: mapServerExcType,
		resolveIdentifierInput: resolveIdentifierInput,
		resolveButtonMount: resolveButtonMount,
		pickVisibleSection: pickVisibleSection,
		CeremonyState: CeremonyState,
		LOGIN_STATES: LOGIN_STATES,
		loginStatusView: loginStatusView,
		LoginStatus: LoginStatus,
		loginStatusForDomCode: loginStatusForDomCode,
		loginStatusForServerKind: loginStatusForServerKind,
		credentialIdB64url: credentialIdB64url,
		buildUnknownCredentialSignal: buildUnknownCredentialSignal,
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
		serverMessages: serverMessages,
		parseConfirmationRequired: parseConfirmationRequired,
		buildGrantHeaders: buildGrantHeaders,
		confirmSignature: confirmSignature,
		extractGrant: extractGrant,
		confirmCapabilities: confirmCapabilities,
		confirmationActionContext: confirmationActionContext,
		normalizeConfirmationSummary: normalizeConfirmationSummary,
		ConfirmError: ConfirmError,
		createConfirmEngine: createConfirmEngine,
	};
});
