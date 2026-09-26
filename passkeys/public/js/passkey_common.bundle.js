// Shared WebAuthn helpers, side-effect-free at load. Published as `frappe.passkeys_common`
// (CommonJS for node tests); loads before every other passkeys bundle.
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) module.exports = api;
	if (typeof window !== "undefined") {
		window.frappe = window.frappe || {};
		window.frappe.passkeys_common = api;
	}
})(typeof self !== "undefined" ? self : this, function () {
	"use strict";

	// ------------------------------------------------------------------ i18n
	// window.__ (frappe._) loads before every web_include_js entry; identity otherwise.
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
		if (pad) b64 += "====".slice(pad);
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

	// Creation options: the native L3 static, else decode the base64url members.
	function parseCreationOptionsFromJSON(json, PKC) {
		var Cred = PKC || (typeof window !== "undefined" ? window.PublicKeyCredential : undefined);
		if (Cred && typeof Cred.parseCreationOptionsFromJSON === "function") {
			return Cred.parseCreationOptionsFromJSON(json);
		}
		var out = Object.assign({}, json);
		out.challenge = b64urlToBytes(json.challenge);
		if (json.user && json.user.id) out.user = Object.assign({}, json.user, { id: b64urlToBytes(json.user.id) });
		if (Array.isArray(json.excludeCredentials)) {
			out.excludeCredentials = json.excludeCredentials.map(function (c) {
				return { type: c.type || "public-key", id: b64urlToBytes(c.id), transports: c.transports };
			});
		}
		return out;
	}

	// ------------------------------------------------------------ gestures
	// navigator.credentials.get()/create() from the server's JSON options, serialized back
	// to JSON. `opts` may carry `mediation` and `signal`. The browser call stays in the
	// caller's task so a click's user activation is not lost.
	function getAssertion(optionsJSON, opts) {
		return credentialRequest("get", function () {
			return parseRequestOptionsFromJSON(optionsJSON);
		}, opts).then(authAssertionToJSON);
	}

	function createCredential(optionsJSON, opts) {
		return credentialRequest("create", function () {
			var publicKey = parseCreationOptionsFromJSON(optionsJSON);
			// py_webauthn emits no extensions; credProps fills the discoverable tri-state.
			publicKey.extensions = Object.assign({}, publicKey.extensions, { credProps: true });
			return publicKey;
		}, opts).then(registrationResponseToJSON);
	}

	function credentialRequest(kind, buildPublicKey, opts) {
		var credentials = typeof navigator !== "undefined" ? navigator.credentials : null;
		var request;
		try {
			if (!credentials || typeof credentials[kind] !== "function") throw namedError("NotSupportedError");
			request = { publicKey: buildPublicKey() };
		} catch (e) {
			return Promise.reject(e);
		}
		if (opts && opts.mediation) request.mediation = opts.mediation;
		if (opts && opts.signal) request.signal = opts.signal;
		return credentials[kind](request).then(function (cred) {
			if (!cred) throw namedError("NotAllowedError");
			return cred;
		});
	}

	function namedError(name) {
		var e = new Error(name);
		e.name = name;
		return e;
	}

	// ------------------------------------------------------------ transport
	// Same-origin POST that leaves the 401 retry-contract body to the caller. Resolves
	// {ok, status, body} for any HTTP status; rejects only on a transport failure.
	function post(method, body, headers) {
		return fetch("/api/method/" + method, {
			method: "POST",
			headers: Object.assign(jsonHeaders(), headers),
			credentials: "same-origin",
			body: JSON.stringify(body || {}),
		}).then(function (resp) {
			return resp.json().catch(function () { return null; }).then(function (json) {
				return { ok: resp.ok, status: resp.status, body: json };
			});
		});
	}

	function jsonHeaders() {
		var headers = { "Content-Type": "application/json", Accept: "application/json" };
		var f = (typeof window !== "undefined" && window.frappe) || {};
		var token = f.csrf_token || (f.boot && f.boot.csrf_token) || (f.session && f.session.csrf_token);
		// Guests are CSRF-exempt; a guest page renders the token as "None".
		if (token && token !== "None") headers["X-Frappe-CSRF-Token"] = token;
		return headers;
	}

	function escapeHtml(s) {
		return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
			return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
		});
	}

	// ---------------------------------------------------- feature detection
	// Layered, never a single signal (the iOS 26.2 isUVPAA regression class):
	// getClientCapabilities() (an absent key stays unknown), then the older statics
	// isConditionalMediationAvailable / isUVPAA for whatever is still unknown.
	function detectCapabilities(env) {
		env = env || {};
		var win = env.window || (typeof window !== "undefined" ? window : {});
		var PKC = env.PublicKeyCredential || win.PublicKeyCredential;
		var result = { supported: false, conditionalMediation: null, uvpaa: null, hybrid: null };
		if (!PKC) return Promise.resolve(result);
		result.supported = true;

		function staticProbes() {
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
					if ("conditionalGet" in caps) result.conditionalMediation = !!caps.conditionalGet;
					if ("userVerifyingPlatformAuthenticator" in caps) {
						result.uvpaa = !!caps.userVerifyingPlatformAuthenticator;
					}
					if ("hybridTransport" in caps) result.hybrid = !!caps.hybridTransport;
					return staticProbes();
				})
				.catch(function () { return staticProbes(); });
		}
		return staticProbes();
	}

	// ------------------------------------------------------- error mapping
	// Map a get()/create() DOMException to the fixed rejection taxonomy.
	function mapDomException(err) {
		var name = err && (err.name || err.code);
		switch (name) {
			case "NotAllowedError": // cancel and timeout are indistinguishable by design
				return { code: "user_cancelled", messageKey: "Couldn't use a passkey — sign in another way." };
			case "AbortError":
				return { code: "user_cancelled", messageKey: "Passkey sign-in was cancelled." };
			case "InvalidStateError":
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
	var CEREMONY_EXPIRED_MESSAGE = "That took too long — please try again.";
	function mapServerExcType(excType) {
		switch (excType) {
			case "CeremonyExpired":
				return "ceremony_expired";
			case "UnknownCredential":
				return "unknown_credential";
			case "UVSetupRequired":
				return "uv_setup_required";
			case "PasskeyConfirmationRequired":
				return "confirmation_required";
			case "PasskeyServedByCore":
				return "served_by_core";
			default:
				return "unknown";
		}
	}

	// -------------------------------------------------- selector resolution
	// A selector miss returns null and callers skip the patch — never throw.
	function resolveIdentifierInput(doc) {
		return doc ? doc.querySelector("#login_email") : null; // same id on v15, v16 and develop
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

	// The section login.route() currently shows (others are display:none), else the first.
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
		if (el.style && (el.style.display === "none" || el.style.visibility === "hidden")) return false;
		var win = el.ownerDocument && el.ownerDocument.defaultView;
		if (win && typeof win.getComputedStyle === "function") {
			var cs = win.getComputedStyle(el);
			if (cs && (cs.display === "none" || cs.visibility === "hidden")) return false;
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
	// Bounded automatic re-arm after a failed verify; false once the cap is hit.
	CeremonyState.prototype.canRearm = function () {
		return this.rearmCount < this.maxRearm;
	};
	CeremonyState.prototype.markRearm = function () {
		this.rearmCount += 1;
		return this.rearmCount;
	};

	// -------------------------------------------------- login status machine
	// One copy string per state feeds both the visible status and the aria-live region, so
	// sighted and screen-reader users get the same message. Every error names a way out.
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
		// Enumeration-safe: "didn't work here", never "isn't registered".
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
		this.state = opts && LOGIN_STATES[opts.state] ? opts.state : "idle";
	}
	LoginStatus.prototype.can = function (next) {
		if (next === this.state) return true;
		var allowed = LOGIN_TRANSITIONS[this.state] || [];
		return allowed.indexOf(next) !== -1;
	};
	// Transition and return the view to paint; an illegal or unknown target stays put.
	LoginStatus.prototype.to = function (next) {
		if (LOGIN_STATES[next] && this.can(next)) this.state = next;
		return loginStatusView(this.state);
	};
	LoginStatus.prototype.view = function () { return loginStatusView(this.state); };

	function loginStatusForDomCode(code) {
		if (code === "not_supported") return "unsupported";
		if (code === "user_cancelled" || code === "no_credentials") return "cancelled";
		return "failed";
	}

	// Every server refusal but unknown_credential collapses to "failed" (enumeration-safe).
	function loginStatusForServerKind(kind) {
		return kind === "unknown_credential" ? "removed" : "failed";
	}

	// ------------------------------------------------------- signal builders
	function credentialIdB64url(cred) {
		if (!cred) return null;
		if (typeof cred.id === "string" && cred.id) return cred.id;
		if (cred.rawId) {
			try { return bytesToB64url(cred.rawId); } catch (e) { return null; }
		}
		return null;
	}

	// userHandle is a base64url string in JSON, an ArrayBuffer on a live credential.
	function assertionHasUserHandle(cred) {
		var r = cred && cred.response;
		if (!r) return false;
		var uh = r.userHandle;
		if (uh == null) return false;
		if (typeof uh === "string") return uh.length > 0;
		if (typeof uh.byteLength === "number") return uh.byteLength > 0;
		return true;
	}

	// signalUnknownCredential payload, or null to skip. UnknownCredential covers both "row
	// not found" (safe to prune) and "no userHandle" (may still be live); only a returned
	// userHandle proves the first, so a valid passkey is never hidden.
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
	// Returns restore(): refocus whatever was active before the OS sheet or dialog opened.
	function captureFocus(doc) {
		var prev = doc && doc.activeElement;
		return function restore() {
			if (prev && typeof prev.focus === "function") {
				try { prev.focus(); } catch (e) { /* element gone */ }
			}
		};
	}

	// ------------------------------------------------------- version-native icons
	// Native-first icons: the first <symbol> present in the host sprite (develop/v16 lucide
	// names, then v15 names), else the inline SVG below; v15 has no key glyph.
	var ICON_SYMBOLS = {
		pencil: ["icon-pencil", "icon-edit"],
		trash: ["icon-trash", "icon-delete"],
		key: ["icon-key"],
	};

	// Lucide artwork (ISC). fill/stroke are pinned inline because Frappe's `.icon` flips them
	// per version (v15 fills), which would turn outline art solid; <use> icons are not pinned.
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
	// The action-confirmation engine: begin -> gesture -> verify -> grant, the 401 retry
	// with fingerprint echo, and concurrency dedupe. The UI and transport are injected.

	var GRANT_HEADER = "X-Passkey-Grant"; // mirrors session.GRANT_HEADER

	var CONFIRM_METHODS = {
		begin: "passkeys.confirm.begin_confirmation",
		verify: "passkeys.confirm.verify_confirmation",
		reauth: "passkeys.confirm.reauth_password",
	};

	// The 401 retry-contract exc_type and the fixed rejection codes apps program against.
	var CONFIRM_EXC_TYPE = "PasskeyConfirmationRequired";
	var CONFIRM_CODES = {
		USER_CANCELLED: "user_cancelled",
		NOT_SUPPORTED: "not_supported",
		NO_CREDENTIALS: "no_credentials",
		CONFIRMATION_FAILED: "confirmation_failed",
		FALLBACK_UNAVAILABLE: "fallback_unavailable",
		NETWORK: "network",
	};

	// Success payloads arrive as {message: ...}; typed-error keys sit at the top level.
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

	// The 401 retry contract, or null. payload_fingerprint is echoed verbatim; JS never hashes.
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

	function buildGrantHeaders(token) {
		var h = {};
		if (token) h[GRANT_HEADER] = token;
		return h;
	}

	// Local dedupe key so concurrent identical calls share one dialog; never sent to the server.
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

	function extractGrant(body) {
		var m = unwrapMessage(body);
		return (m && typeof m === "object" && m.grant) || null;
	}

	// methods ⊆ ["passkey", "password", "sudo"], from begin_confirmation or a 401 body.
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

	var MAX_PASSWORD_TRIES = 5;

	// deps: post(method, body, headers) -> Promise<{ok, status, body}>;
	// runGesture(optionsJSON) -> Promise<assertionJSON>; ui: a controller, or a factory for
	// one per ceremony (contract: docs/custom-ui.md); translate (optional).
	function createConfirmEngine(deps) {
		var post = deps.post;
		var runGesture = deps.runGesture;
		var makeUI = deps.ui;
		var tr = deps.translate || function (s) { return s; };

		var inflight = {}; // signature -> Promise: identical concurrent calls share one
		var chain = Promise.resolve(); // distinct confirmations run one after another

		function reject(code, msg) {
			return Promise.reject(new ConfirmError(code, tr(msg || code)));
		}

		function ui() {
			return typeof makeUI === "function" ? makeUI() : makeUI;
		}

		function mapGestureError(err) {
			if (err && err.code && CODE_SET[err.code]) return err;
			var mapped = mapDomException(err);
			return new ConfirmError(mapped.code, tr(mapped.messageKey));
		}

		// input: {action, params} from confirm(), or the parsed 401 from call().
		function ceremony(input) {
			var action = input.action;
			var beginBody = input.payloadFingerprint
				? { action: action, payload_hash: input.payloadFingerprint }
				: { action: action, params: input.params || {} };

			return post(CONFIRM_METHODS.begin, beginBody, {}).then(function (res) {
				if (!res || !res.ok) {
					var parsed = res && parseConfirmationRequired(res.body);
					if (res && res.status === 417) return reject(CONFIRM_CODES.NOT_SUPPORTED, "Passkey confirmation isn't available here.");
					if (parsed) return reject(CONFIRM_CODES.CONFIRMATION_FAILED, "Couldn't start confirmation.");
					return reject(CONFIRM_CODES.NETWORK, "Couldn't reach the confirmation service — try again.");
				}
				var begin = unwrapMessage(res.body) || {};
				var stateId = begin.state_id;
				var options = begin.options;
				var fingerprint = begin.payload_fingerprint || input.payloadFingerprint || null;
				// The protected action's own 401 carries its display metadata; keep it when
				// begin (possibly on another worker) knows only the default.
				var actionLabel = input.actionLabel ||
					(typeof begin.action_label === "string" ? begin.action_label : null);
				var parameterSummary = input.parameterSummary !== undefined && input.parameterSummary !== null
					? input.parameterSummary : begin.parameter_summary;
				var displayContext = {
					action: action,
					actionLabel: actionLabel,
					parameterSummary: parameterSummary,
				};
				// begin's per-user methods are authoritative; the 401 hint is the fallback.
				var caps = confirmCapabilities(
					Array.isArray(begin.methods) ? begin.methods : input.methods
				);
				if (!caps.passkey && !caps.password) {
					return reject(CONFIRM_CODES.FALLBACK_UNAVAILABLE,
						"This needs you to confirm it's you, but this sign-in can't be confirmed " +
						"with a passkey or password. Sign in again with your password or a passkey, then try again.");
				}
				var controller = ui();
				return Promise.resolve()
					.then(function () {
						if (!caps.passkey) return "password";
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
						// An assertion is never re-POSTed; a retry is a fresh ceremony.
						controller.announce(tr("That didn't work — please try again."));
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							serverMessages(res && res.body) ||
								tr(mapServerExcType(res && res.body && res.body.exc_type) === "ceremony_expired"
								? CEREMONY_EXPIRED_MESSAGE
								: "That passkey didn't confirm it's you. Try again, or use your password."));
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
						if (tries >= MAX_PASSWORD_TRIES) {
							throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED, tr("Too many attempts. Try again later."));
						}
						controller.passwordError(tr("That password wasn't right. Try again."));
						return attempt();
					});
				});
			}
			return attempt();
		}

		function run(input) {
			var sig = confirmSignature(input.action, input.params, input.payloadFingerprint);
			if (inflight[sig]) return inflight[sig];
			var p = chain.then(function () { return ceremony(input); });
			inflight[sig] = p;
			var clear = function () { if (inflight[sig] === p) delete inflight[sig]; };
			p.then(clear, clear);
			chain = p.then(function () {}, function () {});
			return p;
		}

		function confirm(action, params) {
			return run({ action: action, params: params || {} });
		}

		// On the 401 contract: confirm, then retry once with the grant header.
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
						// e.g. the last-passkey guard, which runs after the sudo gate.
						throw new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
							serverMessages(res2 && res2.body) ||
								tr("We confirmed it's you, but the action still didn't go through — please try again."));
					});
				});
			}, function () {
				throw new ConfirmError(CONFIRM_CODES.NETWORK, tr("Couldn't reach the server — try again."));
			});
		}

		// A server that answered and refused is confirmation_failed, never network.
		function httpError(res) {
			return new ConfirmError(CONFIRM_CODES.CONFIRMATION_FAILED,
				serverMessages(res && res.body) ||
					tr("The action couldn't be confirmed — please try again."));
		}

		return { confirm: confirm, call: call };
	}

	var CODE_SET = {};
	Object.keys(CONFIRM_CODES).forEach(function (k) { CODE_SET[CONFIRM_CODES[k]] = true; });

	return {
		t: t,
		mergeAppTranslations: mergeAppTranslations,
		loadAppTranslations: loadAppTranslations,
		b64urlToBytes: b64urlToBytes,
		bytesToB64url: bytesToB64url,
		parseRequestOptionsFromJSON: parseRequestOptionsFromJSON,
		authAssertionToJSON: authAssertionToJSON,
		registrationResponseToJSON: registrationResponseToJSON,
		parseCreationOptionsFromJSON: parseCreationOptionsFromJSON,
		getAssertion: getAssertion,
		createCredential: createCredential,
		post: post,
		escapeHtml: escapeHtml,
		detectCapabilities: detectCapabilities,
		mapDomException: mapDomException,
		mapServerExcType: mapServerExcType,
		CEREMONY_EXPIRED_MESSAGE: CEREMONY_EXPIRED_MESSAGE,
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
		GRANT_HEADER: GRANT_HEADER,
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
