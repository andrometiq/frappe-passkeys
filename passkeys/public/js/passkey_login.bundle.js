// /login: conditional UI, the explicit button, cross-device, the password -> passkey second
// factor and the uv-setup step-up. Loads after passkey_common and frappe-web.bundle.js;
// boots once on login_rendered (DOMContentLoaded fallback). Any failure leaves the core
// password form untouched.
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	if (!C) return;
	var t = C.t;
	var escapeHtml = C.escapeHtml;

	// -------------------------------------------------------------- constants
	var API = {
		begin_login: "passkeys.passkey.begin_login",
		verify_login: "passkeys.passkey.verify_login",
		complete_uv_setup: "passkeys.passkey.complete_uv_setup",
		login_with_password: "passkeys.passkey.login_with_password",
		verify_second_factor: "passkeys.passkey.verify_second_factor",
		fallback_to_otp: "passkeys.passkey.fallback_to_otp",
	};
	var HINT_KEY = "passkey_used_here"; // localStorage promote-only hint
	// Mirrors passkey_manage_common UPSELL_FLAG_KEY (not loaded on /login); a node spec pins equality.
	var UPSELL_FLAG_KEY = "passkey_upsell_add_local";
	var STATUS_ID = "passkey-login-status";
	var SLOW_MS = 4000; // "still verifying" escalation on a slow connection
	var BOOTED = false;

	var state = {
		modes: { first_factor: false, second_factor: false },
		login: new C.CeremonyState({ ttlMs: 300000 }),
		status: new C.LoginStatus(),
		slowTimer: null,
		conditionalAbort: null, // AbortController for the pending conditional get()
		conditionalEnabled: false,
		sfInterceptor: null, // the capture-phase submit listener
		busyModal: false, // a modal get() is in flight
		rebeginInFlight: null, // the pending re-begin, shared by concurrent callers
	};

	// -------------------------------------------------------------- boot glue
	function boot() {
		if (BOOTED) return;
		BOOTED = true;
		try { if (window.localStorage) localStorage.removeItem(UPSELL_FLAG_KEY); } catch (e) { /* ignore */ }
		C.ensureLiveRegion(document);
		// Web pages on v15/v16 ship no app strings: merge the catalog first.
		C.loadAppTranslations().then(start);
	}

	// login_rendered, else (a custom template) DOMContentLoaded.
	document.addEventListener("login_rendered", boot, { once: true });
	window.addEventListener("pageshow", onPageShow);
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", function () {
			setTimeout(function () { if (!BOOTED) boot(); }, 0);
		});
	} else {
		setTimeout(function () { if (!BOOTED) boot(); }, 0);
	}

	function onPageShow(event) {
		if (!event || !event.persisted) return;
		abortConditional();
		state.busyModal = false;
		state.login.markSpent();
		if (state.modes.first_factor) rebeginAndRearm();
	}

	// ------------------------------------------------------------- main start
	function start() {
		detect().then(function (caps) {
			beginLogin().then(function (cfg) {
				if (!cfg || !cfg.enabled) {
					removeSelf();
					return;
				}
				state.modes = cfg.modes || state.modes;

				if (state.modes.second_factor) {
					installSecondFactorInterception();
				}

				if (state.modes.first_factor && caps.supported) {
					if (cfg.state_id && cfg.options) {
						state.login.adopt(cfg.state_id, cfg.options, Date.now());
					}
					ensureStatusEl();
					// Conditional UI first, unless explicitly unavailable.
					state.conditionalEnabled = caps.conditionalMediation !== false;
					if (state.conditionalEnabled) {
						startConditional();
					}
					mountButton(caps);
				}
			}, noop);
		}, noop);
	}

	function detect() {
		return C.detectCapabilities({ window: window }).catch(function () {
			return { supported: false, conditionalMediation: null, uvpaa: null, hybrid: null };
		});
	}

	// The silent config channel: {enabled, modes, state_id?, options?}, or null on any
	// failure (429/5xx/network degrade like enabled:false).
	function beginLogin() {
		return C.post(API.begin_login, {}).then(function (res) {
			return res.ok ? C.unwrapMessage(res.body) : null;
		}).catch(function () { return null; });
	}

	// ------------------------------------------------------- conditional UI
	function startConditional() {
		// Overlapping get() calls make the browser abort one; the open modal owns the authenticator.
		if (!state.conditionalEnabled || state.busyModal) return;
		// A selector miss (a core redesign) skips conditional UI; the button still works.
		var input = C.resolveIdentifierInput(document);
		if (!input) return;
		var ac = input.getAttribute("autocomplete") || "username";
		if (ac.indexOf("webauthn") === -1) input.setAttribute("autocomplete", (ac + " webauthn").trim());
		if (!navigator.credentials || typeof navigator.credentials.get !== "function") return;
		var stateId = state.login.stateId;
		var options = state.login.options;
		if (!stateId || !options) return;

		abortConditional();
		var controller = new AbortController();
		state.conditionalAbort = controller;
		var publicKey;
		try {
			publicKey = C.parseRequestOptionsFromJSON(options, window.PublicKeyCredential);
		} catch (e) { state.login.markSpent(stateId); return; }

		navigator.credentials
			.get({ mediation: "conditional", publicKey: publicKey, signal: controller.signal })
			.then(function (cred) {
				state.conditionalAbort = null;
				runVerify(cred, { source: "conditional" }, stateId);
			})
			.catch(function (err) {
				state.conditionalAbort = null;
				// We abort it for a modal get or a re-begin. Other failures stay silent: the
				// user made no gesture yet.
				if (err && err.name === "AbortError") return;
				state.login.markSpent(stateId);
			});
	}

	function abortConditional() {
		if (state.conditionalAbort) {
			try { state.conditionalAbort.abort(); } catch (e) { /* noop */ }
			state.conditionalAbort = null;
		}
	}

	// ------------------------------------------------------- explicit button
	function mountButton(caps) {
		if (document.getElementById("passkey-login-btn")) return;
		var target = C.resolveButtonMount(document);
		if (!target) return;

		var btn = document.createElement("button");
		btn.type = "button";
		btn.id = "passkey-login-btn";
		btn.className = "btn btn-sm btn-block btn-login-option btn-passkey-login";
		btn.setAttribute("aria-label", t("Sign in with a passkey"));
		// Inline key glyph: the #icon-key sprite is blank on v15 (no web_include_icons).
		btn.innerHTML =
			C.iconSvg("key", "icon icon-sm passkey-glyph") +
			'<span class="passkey-label"></span>';
		btn.querySelector(".passkey-label").textContent = t("Sign in with a passkey");

		// The used-here hint only moves the button to the top; it never hides it.
		var promote = false;
		try { promote = window.localStorage && localStorage.getItem(HINT_KEY) === "1"; } catch (e) { /* ignore */ }

		if (target.mode === "actions" || target.mode === "providers") {
			// First among the alternative sign-in methods (FIDO UX principle 8).
			var firstAlt = target.mount.querySelector(".btn-login-option, .social-logins, .btn-ldap-login");
			if (firstAlt && !promote) {
				target.mount.insertBefore(btn, firstAlt);
			} else {
				target.mount.insertBefore(btn, target.mount.firstChild);
			}
		} else {
			target.mount.appendChild(btn);
		}

		btn.addEventListener("click", onButtonClick);
	}

	function onButtonClick(e) {
		if (e) {
			e.preventDefault();
			e.stopPropagation();
			if (e.stopImmediatePropagation) e.stopImmediatePropagation();
		}
		if (state.busyModal) return;
		abortConditional(); // Chromium rejects overlapping requests
		modalGet({ source: "button" });
	}

	// ------------------------------------------- modal get() with pre-freshness
	// A spent or stale state is replaced BEFORE the gesture: one gesture, not two failures.
	function modalGet(ctx) {
		var proceed = function () {
			if (state.busyModal) return; // a click that joined a shared re-begin already opened get()
			var stateId = state.login.stateId;
			var options = state.login.options;
			if (!stateId || !options) {
				state.login.markSpent(stateId);
				announce(t("Passkeys aren't available right now."));
				return;
			}
			var publicKey;
			try {
				publicKey = C.parseRequestOptionsFromJSON(options, window.PublicKeyCredential);
			} catch (e) {
				state.login.markSpent(stateId);
				announce(t("Couldn't start passkey sign-in — try again or sign in another way."));
				return;
			}
			state.busyModal = true;
			abortConditional(); // a re-arm sharing this re-begin may have started conditional UI
			var restore = C.captureFocus(document);
			applyLoginStatus("waiting");
			navigator.credentials
				.get({ publicKey: publicKey })
				.then(function (cred) {
					state.busyModal = false;
					restore();
					runVerify(cred, ctx, stateId);
				})
				.catch(function (err) {
					state.busyModal = false;
					restore();
					state.login.markSpent(stateId);
					onCeremonyError(err);
				});
		};

		if (state.login.needsPreModalRebegin(Date.now())) {
			rebegin().then(function (ok) { if (ok) proceed(); else announce(t("Passkeys aren't available right now.")); });
		} else {
			proceed();
		}
	}

	// Fetch a fresh state without a gesture. Single-flight: a click never races an automatic
	// re-arm (or another click) with a second begin_login.
	function rebegin() {
		if (state.rebeginInFlight) return state.rebeginInFlight;
		state.rebeginInFlight = beginLogin().then(function (cfg) {
			state.rebeginInFlight = null;
			if (cfg && cfg.enabled && cfg.modes && cfg.modes.first_factor && cfg.state_id && cfg.options) {
				state.modes = cfg.modes;
				state.login.adopt(cfg.state_id, cfg.options, Date.now());
				return true;
			}
			return false;
		}, function () { state.rebeginInFlight = null; return false; });
		return state.rebeginInFlight;
	}

	// ------------------------------------------------------ verify (first factor)
	function runVerify(cred, ctx, stateId) {
		var attachment = cred && cred.authenticatorAttachment;
		var assertion;
		try {
			assertion = C.authAssertionToJSON(cred);
		} catch (e) {
			state.login.markSpent(stateId);
			applyLoginStatus("failed");
			return;
		}
		state.login.markSpent(stateId);
		var payload = { state_id: stateId, credential: JSON.stringify(assertion) };

		applyLoginStatus("verifying");
		armSlowTimer();

		// Only 200 and the typed 401s have handlers. Any other outcome (plain 401, 417/429/5xx,
		// transport failure) must not leave "Verifying…" up, so an unclaimed settle is "failed".
		var claimed = false;
		function finishVerify() {
			if (claimed) return;
			clearSlowTimer();
			var s = state.status.state;
			if (s === "verifying" || s === "verifying_slow" || s === "waiting") {
				applyLoginStatus("failed");
			}
		}

		var call = frappeCall(API.verify_login, payload, composedHandlers({
			on401: function (data) { claimed = true; clearSlowTimer(); handleFirstFactor401(data, ctx, attachment, cred); },
			// "You're in", painted before core's 200 handler starts the redirect.
			onSuccessEarly: function () { claimed = true; clearSlowTimer(); applyLoginStatus("success"); },
			onSuccess: function () {
				rememberHint();
				postLoginUpsell(attachment);
			},
		}));

		// frappe.call's thenable settles after the statusCode handler on every outcome.
		call.then(finishVerify, finishVerify);
	}

	function handleFirstFactor401(data, ctx, attachment, cred) {
		var kind = C.mapServerExcType(data && data.exc_type);
		if (kind === "ceremony_expired") {
			// At most one fresh ceremony; an assertion is never re-POSTed.
			if (state.login.canRearm()) {
				rebegin().then(function (ok) {
					if (!ok) { neutralFail(); return; }
					state.login.markRearm();
					if (ctx.source === "button") modalGet(ctx);
					else startConditional();
				});
			} else {
				neutralFail();
			}
			return;
		}
		if (kind === "unknown_credential") {
			// On the device but gone from the server: say so and ask the provider to prune it.
			signalUnknownCredential(cred);
			applyLoginStatus(C.loginStatusForServerKind(kind));
			rearmAfterVisibleFailure();
			return;
		}
		if (kind === "uv_setup_required") {
			applyLoginStatus("idle"); // the password step-up dialog takes over
			openUvSetup(data && data.setup_id);
			return;
		}
		// Re-arm once so the user is never dead-ended.
		neutralFail();
		rearmAfterVisibleFailure();
	}

	// After a visible failure that spent the state, re-begin once (bounded, never a loop).
	function rearmAfterVisibleFailure() {
		if (!state.login.canRearm()) return;
		rebegin().then(function (ok) {
			if (!ok) return;
			state.login.markRearm();
			startConditional();
		});
	}

	// ---------------------------------------------- uv-setup step-up
	function openUvSetup(setupId) {
		if (!setupId) { neutralFail(); return; }
		var restore = C.captureFocus(document);
		var dlg = buildDialog({
			titleText: t("Finish setting up this passkey"),
			bodyHtml:
				"<p>" + escapeHtml(t("Confirm your password once to finish setting up this passkey.")) + "</p>" +
				'<div class="form-group"><label class="form-label" for="passkey-uv-pwd">' +
				escapeHtml(t("Password")) + '</label>' +
				'<input type="password" id="passkey-uv-pwd" class="form-control" autocomplete="current-password"></div>' +
				'<p class="passkey-dialog-error" role="alert"></p>',
			primaryText: t("Confirm"),
			onPrimary: function (root, close) {
				var pwd = root.querySelector("#passkey-uv-pwd").value;
				if (!pwd) { setDialogError(root, t("Password is required.")); return; }
				frappeCall(API.complete_uv_setup, { setup_id: setupId, pwd: pwd },
					composedHandlers({
						on401: function (d) {
							var k = C.mapServerExcType(d && d.exc_type);
							if (k === "ceremony_expired") {
								close(); neutralFail();
								rebeginAndRearm();
							} else {
								setDialogError(root, t("That didn't work — check your password and try again."));
							}
						},
						onSuccess: function () { rememberHint(); close(); }, // core's 200 handler redirects
					})
				);
			},
			onClose: restore,
		});
		openDialog(dlg);
		dlg.root.querySelector("#passkey-uv-pwd").focus();
	}

	// ----------------------------------------- second factor interception
	function installSecondFactorInterception() {
		if (state.sfInterceptor) return;
		state.sfInterceptor = function (event) {
			var form = event.target && event.target.closest && event.target.closest(".form-login");
			if (!form) return;
			// Any error removes the listener and lets this submit proceed natively.
			try {
				var usr = valueOf("#login_email");
				var pwd = valueOf("#login_password");
				if (!usr || !pwd) return; // core validates empty fields
				event.preventDefault();
				event.stopImmediatePropagation();
				loginWithPassword(usr, pwd);
			} catch (e) {
				removeSecondFactorInterception();
			}
		};
		document.addEventListener("submit", state.sfInterceptor, true); // capture phase
		document.documentElement.setAttribute("data-passkeys-second-factor-ready", "true");
	}

	function removeSecondFactorInterception() {
		if (state.sfInterceptor) {
			document.removeEventListener("submit", state.sfInterceptor, true);
			state.sfInterceptor = null;
		}
		document.documentElement.removeAttribute("data-passkeys-second-factor-ready");
	}

	function loginWithPassword(usr, pwd) {
		announce(t("Verifying…"));
		frappeCall(API.login_with_password, { usr: usr, pwd: pwd }, composedHandlers({
			on401: coreDelegate401, // mode off or bad credentials: core's painter
			onSuccess: function (data) {
				// Core's 200 handler already covers Logged In / OTP / SMS / Email.
				if (data && data.verification && data.verification.method === "Passkey") {
					driveSecondFactor(data);
				}
			},
		}));
	}

	// Leg 2: a modal get() -> verify_second_factor, with server re-arm and OTP fallback.
	function driveSecondFactor(env) {
		var verification = env.verification || {};
		var tmpId = env.tmp_id;
		var options = verification.options;
		var fallbackOtp = verification.fallback && verification.fallback.otp;
		if (!secondFactorWebAuthnAvailable()) {
			showSecondFactorUnavailable(tmpId, fallbackOtp);
			return;
		}
		runSecondFactorCeremony(tmpId, options, fallbackOtp);
	}

	function secondFactorWebAuthnAvailable() {
		return !!(window.PublicKeyCredential && navigator.credentials &&
			typeof navigator.credentials.get === "function");
	}

	// No WebAuthn is a routing decision, not a ceremony error: OTP when the server allows it,
	// else an explicit way back to the login form.
	function showSecondFactorUnavailable(stateId, fallbackOtp) {
		var restore = C.captureFocus(document);
		var canUseOtp = fallbackOtp === true || fallbackOtp === 1;
		var dlg = buildDialog({
			titleText: canUseOtp ? t("Use a verification code") : t("Passkey verification unavailable"),
			bodyHtml: '<p class="passkey-dialog-error" role="alert">' + escapeHtml(canUseOtp
				? t("Passkeys aren't supported on this device. Use a verification code to finish signing in.")
				: t("Passkeys aren't supported on this device, and no verification-code fallback is available. Contact your administrator or return to sign in.")) + '</p>',
			primaryText: canUseOtp ? t("Use a verification code") : t("Back to sign in"),
			onPrimary: canUseOtp
				? function (root, close) { requestOtpFallback(stateId, root, close); }
				: function (root, close) { close(); window.location.reload(); },
			onClose: restore,
		});
		openDialog(dlg);
		announce(canUseOtp
			? t("Passkeys aren't supported on this device. Use a verification code to finish signing in.")
			: t("Passkey verification is unavailable. Contact your administrator or return to sign in."));
	}

	function requestOtpFallback(stateId, root, close) {
		if (root._passkeyOtpPending) return;
		root._passkeyOtpPending = true;
		var claimed = false;
		setDialogError(root, t("Opening verification-code sign-in..."));
		var call = frappeCall(API.fallback_to_otp, { state_id: stateId },
			composedHandlers({
				on401: function (d) { claimed = true; close(); coreDelegate401(d); },
				// Core's 200 handler paints the OTP/SMS/Email form.
				onSuccess: function () { claimed = true; close(); },
			})
		);
		function finish() {
			if (claimed) return;
			root._passkeyOtpPending = false;
			setDialogError(root, t("Couldn't open verification-code sign-in. Return to sign in or contact your administrator."));
		}
		call.then(finish, finish);
	}

	function runSecondFactorCeremony(stateId, options, fallbackOtp) {
		var restore = C.captureFocus(document);
		var publicKey;
		try {
			publicKey = C.parseRequestOptionsFromJSON(options, window.PublicKeyCredential);
		} catch (e) { restore(); showSecondFactorUnavailable(stateId, fallbackOtp); return; }

		var dlg = buildDialog({
			titleText: t("Confirm it's you"),
			bodyHtml:
				'<p>' + escapeHtml(t("Use your passkey to finish signing in.")) + '</p>' +
				'<p class="passkey-dialog-error" role="alert"></p>',
			primaryText: t("Use a passkey"),
			secondaryText: fallbackOtp ? t("Use a verification code instead") : null,
			onPrimary: function (root, close, ctxState) {
				if (ctxState.ceremonyPending) return;
				ctxState.ceremonyPending = true;
				announce(t("Waiting for your passkey."));
				Promise.resolve()
					.then(function () {
						if (!secondFactorWebAuthnAvailable()) {
							var unsupported = new Error("WebAuthn unavailable");
							unsupported.name = "NotSupportedError";
							throw unsupported;
						}
						return navigator.credentials.get({ publicKey: publicKey });
					})
					.then(function (cred) {
						var handled = false;
						function settle(message) {
							handled = true;
							ctxState.ceremonyPending = false;
							if (message) setDialogError(root, message);
						}
						var call = frappeCall(API.verify_second_factor,
							{ state_id: ctxState.stateId, credential: JSON.stringify(C.authAssertionToJSON(cred)) },
							composedHandlers({
								on401: function (d) {
									var expired = C.mapServerExcType(d && d.exc_type) === "ceremony_expired";
									var freshOptions = d && d.verification && d.verification.options;
									if (!expired) return settle(t("That passkey couldn't be verified — try again."));
									// The server re-armed: a fresh state rides in the 401 body.
									if (!d.state_id || !freshOptions) { settle(); close(); coreDelegate401(d); return; }
									ctxState.stateId = d.state_id;
									try {
										publicKey = C.parseRequestOptionsFromJSON(freshOptions, window.PublicKeyCredential);
									} catch (e) { /* keep the old options */ }
									settle(t("That didn't work — try your passkey again."));
								},
								on429: function () { settle(t("Too many attempts. Wait a moment, then try again.")); },
								onSuccess: function () { handled = true; rememberHint(); close(); }, // core redirects
							})
						);
						function finish() {
							if (!handled) settle(t("That passkey couldn't be verified — try again."));
						}
						return call.then(finish, finish);
					})
					.catch(function (err) {
						ctxState.ceremonyPending = false;
						var m = C.mapDomException(err);
						if (m.code === "not_supported") {
							close();
							showSecondFactorUnavailable(ctxState.stateId, fallbackOtp);
							return;
						}
						setDialogError(root, t(m.messageKey));
					});
			},
			onSecondary: fallbackOtp ? function (root, close, ctxState) {
				requestOtpFallback(ctxState.stateId, root, close);
			} : null,
			onClose: restore,
			ctxState: { stateId: stateId },
		});
		openDialog(dlg);
	}

	// ------------------------------------------------------- signals (fire-and-forget)
	// Ask the provider to prune the credential the server just rejected.
	function signalUnknownCredential(cred) {
		if (!window.PublicKeyCredential ||
			typeof window.PublicKeyCredential.signalUnknownCredential !== "function") return;
		var payload = C.buildUnknownCredentialSignal(cred, resolveRpId());
		if (!payload) return;
		try {
			var p = window.PublicKeyCredential.signalUnknownCredential(payload);
			if (p && typeof p.catch === "function") {
				p.catch(function (err) { console.debug("Passkey credential prune failed.", err); });
			}
		} catch (e) { /* Firefox absent, etc. */ }
	}

	// The begin_login options carry the RP ID; the host is the fallback.
	function resolveRpId() {
		var opts = state.login.options;
		return (opts && opts.rpId) || window.location.hostname;
	}

	// A cross-device assertion flags "add a passkey to this device" for the desk/portal bundle.
	function postLoginUpsell(attachment) {
		try {
			if (attachment === "cross-platform" && window.localStorage) {
				localStorage.setItem(UPSELL_FLAG_KEY, "1");
			}
		} catch (e) { /* ignore */ }
	}

	// ---------------------------------------------------- frappe.call plumbing
	// core's login.login_handlers with 200/401/429 wrapped: core still paints Logged In /
	// OTP / Password Reset, typed passkey errors route to us, anything else back to core.
	function composedHandlers(app) {
		var base = (window.login && window.login.login_handlers) || {};
		var merged = {};
		for (var code in base) { if (Object.prototype.hasOwnProperty.call(base, code)) merged[code] = base[code]; }

		var base200 = base[200];
		merged[200] = function (data) {
			// Core does not know the Passkey verification method: never let it paint one.
			if (data && data.verification && data.verification.method === "Passkey") {
				if (app.onSuccess) app.onSuccess(data);
				return;
			}
			if (app.onSuccessEarly) { try { app.onSuccessEarly(data); } catch (e) { /* never block core */ } }
			if (base200) { try { base200(data); } catch (e) { /* core handler */ } }
			if (app.onSuccess) app.onSuccess(data);
		};

		merged[401] = function (xhr) {
			var data = (xhr && xhr.responseJSON) || {};
			var kind = C.mapServerExcType(data.exc_type);
			if (kind !== "unknown" && app.on401) {
				app.on401(data);
			} else if (base[401]) {
				base[401](xhr, data);
			}
		};

		merged[429] = function (xhr) {
			if (base[429]) base[429](xhr, (xhr && xhr.responseJSON) || {});
			if (app.on429) app.on429((xhr && xhr.responseJSON) || {});
		};

		return merged;
	}

	function coreDelegate401(data) {
		var base = (window.login && window.login.login_handlers) || {};
		if (base[401]) {
			base[401]({ responseJSON: data }, data);
		} else {
			neutralFail();
		}
	}

	// frappe-web.bundle.js ships frappe.call on /login.
	function frappeCall(method, args, statusCode) {
		return window.frappe.call({ method: method, type: "POST", args: args, freeze: true, statusCode: statusCode });
	}

	// --------------------------------------------------------------- dialog a11y
	// role=dialog + aria-labelledby, focus trap, Esc dismisses, focus returns to the invoker.
	function buildDialog(cfg) {
		var overlay = document.createElement("div");
		overlay.className = "passkey-dialog-overlay";
		var root = document.createElement("div");
		root.className = "passkey-dialog";
		root.setAttribute("role", "dialog");
		root.setAttribute("aria-modal", "true");
		var titleId = "passkey-dialog-title-" + Date.now();
		root.setAttribute("aria-labelledby", titleId);
		root.innerHTML =
			'<h4 id="' + titleId + '" class="passkey-dialog-title"></h4>' +
			'<div class="passkey-dialog-body"></div>' +
			'<div class="passkey-dialog-actions"></div>';
		root.querySelector(".passkey-dialog-title").textContent = cfg.titleText;
		root.querySelector(".passkey-dialog-body").innerHTML = cfg.bodyHtml;
		overlay.appendChild(root);

		var ctxState = cfg.ctxState || {};
		var actions = root.querySelector(".passkey-dialog-actions");

		function close() {
			if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
			document.removeEventListener("keydown", onKey, true);
			if (cfg.onClose) cfg.onClose();
		}

		if (cfg.secondaryText && cfg.onSecondary) {
			var secBtn = document.createElement("button");
			secBtn.type = "button";
			secBtn.className = "btn btn-sm btn-default btn-block";
			secBtn.textContent = cfg.secondaryText;
			secBtn.addEventListener("click", function () { cfg.onSecondary(root, close, ctxState); });
			actions.appendChild(secBtn);
		}
		var primary = document.createElement("button");
		primary.type = "button";
		primary.className = "btn btn-sm btn-primary btn-block";
		primary.textContent = cfg.primaryText;
		primary.addEventListener("click", function () { cfg.onPrimary(root, close, ctxState); });
		actions.appendChild(primary);

		var cancel = document.createElement("button");
		cancel.type = "button";
		cancel.className = "btn btn-sm btn-default btn-block passkey-dialog-cancel";
		cancel.textContent = t("Not now");
		cancel.addEventListener("click", close);
		actions.appendChild(cancel);

		function focusables() {
			return root.querySelectorAll("button, input, a[href], [tabindex]:not([tabindex='-1'])");
		}
		function onKey(e) {
			if (e.key === "Escape") { e.preventDefault(); close(); return; }
			if (e.key === "Tab") {
				var f = focusables();
				if (!f.length) return;
				var first = f[0], last = f[f.length - 1];
				if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
				else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
			}
		}

		return { overlay: overlay, root: root, close: close, primary: primary, onKey: onKey, focusables: focusables };
	}

	function openDialog(dlg) {
		(document.body || document.documentElement).appendChild(dlg.overlay);
		document.addEventListener("keydown", dlg.onKey, true);
		// Focus the primary action unless the caller already focused a field (the uv-setup
		// password), so this deferred call never steals focus mid-typing.
		setTimeout(function () {
			if (dlg.root.contains(document.activeElement)) return;
			if (dlg.primary) dlg.primary.focus();
		}, 0);
	}

	function setDialogError(root, msg) {
		var el = root.querySelector(".passkey-dialog-error");
		if (el) el.textContent = msg;
		announce(msg);
	}

	// ----------------------------------------------------------- error paths / UX
	// A visible state over the untouched form, then one re-arm so the user is never stuck.
	function onCeremonyError(err) {
		applyLoginStatus(C.loginStatusForDomCode(C.mapDomException(err).code));
		rearmAfterVisibleFailure();
	}

	function neutralFail() {
		applyLoginStatus("failed");
	}

	// ------------------------------------------------- visible staged status surface
	// The app's own status element (core's .login-error-banner exists only on develop),
	// just above the login actions; without a mount the aria-live region still covers AT.
	function ensureStatusEl() {
		if (document.getElementById(STATUS_ID)) return;
		var target = C.resolveButtonMount(document);
		if (!target) return;
		var el = document.createElement("div");
		el.id = STATUS_ID;
		el.className = "passkey-status";
		el.hidden = true;
		el.innerHTML =
			'<span class="passkey-status__icon" aria-hidden="true"></span>' +
			'<span class="passkey-status__text"></span>';
		target.mount.parentNode.insertBefore(el, target.mount);
	}

	function statusEl() { return document.getElementById(STATUS_ID); }

	// The one chokepoint: advance the machine, paint the element, announce the same text.
	function applyLoginStatus(stateName) {
		if (stateName !== "verifying") clearSlowTimer();
		var view = state.status.to(stateName);
		var text = view.text ? t(view.text) : "";
		var el = statusEl();
		if (el) {
			var textEl = el.querySelector(".passkey-status__text");
			if (!view.visible || !text) {
				el.hidden = true;
				el.className = "passkey-status";
				if (textEl) textEl.textContent = "";
			} else {
				el.hidden = false;
				el.className = "passkey-status passkey-status--" + view.tone;
				var icon = el.querySelector(".passkey-status__icon");
				if (icon) {
					icon.className = view.tone === "progress"
						? "passkey-status__icon spinner-border spinner-border-sm"
						: "passkey-status__icon";
				}
				if (textEl) textEl.textContent = text;
			}
		}
		if (view.visible && text) announce(text);
	}

	function armSlowTimer() {
		clearSlowTimer();
		state.slowTimer = setTimeout(function () {
			state.slowTimer = null;
			if (state.status.state === "verifying") applyLoginStatus("verifying_slow");
		}, SLOW_MS);
	}

	function clearSlowTimer() {
		if (state.slowTimer) { clearTimeout(state.slowTimer); state.slowTimer = null; }
	}

	function rebeginAndRearm() {
		rebegin().then(function (ok) { if (ok) startConditional(); });
	}

	// -------------------------------------------------------------- small utils
	function announce(msg) { C.announce(document, msg); }
	function rememberHint() { try { if (window.localStorage) localStorage.setItem(HINT_KEY, "1"); } catch (e) { /* ignore */ } }
	function removeSelf() { removeSecondFactorInterception(); abortConditional(); clearSlowTimer(); var s = document.getElementById(STATUS_ID); if (s && s.parentNode) s.parentNode.removeChild(s); var b = document.getElementById("passkey-login-btn"); if (b && b.parentNode) b.parentNode.removeChild(b); }
	function valueOf(sel) { var el = document.querySelector(sel); return el ? (el.value || "").trim() : ""; }
	function noop() {}

	// For the Cypress specs.
	window.frappe = window.frappe || {};
	window.frappe._passkey_login = { boot: boot, _state: state, API: API, applyLoginStatus: applyLoginStatus };

	// Node test seam. The asset build defines `module` in the browser too; keep startup outside this if.
	if (typeof module === "object" && module.exports) {
		module.exports = {
			state: state, runVerify: runVerify, applyLoginStatus: applyLoginStatus,
			armSlowTimer: armSlowTimer, clearSlowTimer: clearSlowTimer, API: API,
			onButtonClick: onButtonClick, modalGet: modalGet, rebegin: rebegin,
			onPageShow: onPageShow,
			secondFactorWebAuthnAvailable: secondFactorWebAuthnAvailable,
			showSecondFactorUnavailable: showSecondFactorUnavailable,
			runSecondFactorCeremony: runSecondFactorCeremony,
			UPSELL_FLAG_KEY: UPSELL_FLAG_KEY,
		};
	}
})();
