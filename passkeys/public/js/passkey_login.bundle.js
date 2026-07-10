// passkey_login.bundle.js — passkey login-page bundle (J1 conditional UI, J2 explicit
// button, J3 cross-device, J4 password->passkey second factor, uv-setup step-up).
//
// Delivered via update_website_context -> context.web_include_js on /login when any mode is
// enabled (§5.1). Loaded AFTER passkey_common.js (which sets frappe.passkeys_common) and
// AFTER frappe-web.bundle.js (which defines window.__). Owns its own lifecycle: boots once on
// login_rendered, with a DOMContentLoaded fallback and an idempotent guard (§5.2). Any JS
// failure degrades to the untouched core password form — the page is never deadened.
//
// The whole file is an IIFE (classic script) so it needs no bundler module resolution and is
// `node --check`-able as-is. Server contracts are the FROZEN spec's pinned wire shapes (§3).
//
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	if (!C) return; // common helpers absent -> no-op, password form untouched
	var t = C.t;

	// -------------------------------------------------------------- constants
	var API = {
		begin_login: "passkeys.passkey.begin_login",
		verify_login: "passkeys.passkey.verify_login",
		complete_uv_setup: "passkeys.passkey.complete_uv_setup",
		login_with_password: "passkeys.passkey.login_with_password",
		verify_second_factor: "passkeys.passkey.verify_second_factor",
		fallback_to_otp: "passkeys.passkey.fallback_to_otp",
		get_signal_data: "passkeys.passkey.get_signal_data",
		app_translations: "passkeys.passkey.get_app_translations",
	};
	var HINT_KEY = "passkey_used_here"; // localStorage promote-only hint (§5.2 step 4)
	var BOOTED = false;

	// bundle-scoped runtime state
	var state = {
		modes: { first_factor: false, second_factor: false },
		login: new C.CeremonyState({ ttlMs: 300000 }),
		conditionalAbort: null, // AbortController for the pending conditional get()
		sfInterceptor: null, // the document capture-phase submit listener
		busyModal: false, // a modal get()/create() is in flight
	};

	// -------------------------------------------------------------- boot glue
	function boot() {
		if (BOOTED) return; // idempotent injection guard (login_rendered is one-shot)
		BOOTED = true;
		C.ensureLiveRegion(document);
		// merge our own guest translation catalog (REQUIRED on v15/v16, §5.6), then start.
		loadAppTranslations()
			.catch(noop) // English fallback is acceptable; never block boot
			.then(start);
	}

	// listen once + DOMContentLoaded fallback (the event is one-shot, §5.2)
	document.addEventListener("login_rendered", boot, { once: true });
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", function () {
			// only if login_rendered never fired (e.g. custom template)
			setTimeout(function () { if (!BOOTED) boot(); }, 0);
		});
	} else {
		setTimeout(function () { if (!BOOTED) boot(); }, 0);
	}

	// ---------------------------------------------------------- i18n loader
	// Fetch the app guest translations endpoint once, memoize, MERGE (never clobber) into
	// frappe._messages (§5.6). On develop, also await frappe._translations_loaded so the
	// core catalog is in place before our first translated paint.
	function loadAppTranslations() {
		var jobs = [];
		if (window.frappe && window.frappe._translations_loaded &&
			typeof window.frappe._translations_loaded.then === "function") {
			jobs.push(window.frappe._translations_loaded.catch(noop));
		}
		var appJob = fetch(methodUrl(API.app_translations), {
			method: "GET",
			headers: { Accept: "application/json" },
			credentials: "same-origin",
		})
			.then(function (r) { return r.ok ? r.json() : null; })
			.then(function (payload) {
				var catalog = payload && (payload.message || payload);
				if (catalog && typeof catalog === "object") {
					C.mergeAppTranslations(window.frappe, catalog);
				}
			})
			.catch(noop);
		jobs.push(appJob);
		return Promise.all(jobs);
	}

	// ------------------------------------------------------------- main start
	function start() {
		detect().then(function (caps) {
			// One begin_login POST — the bundle's only config channel. NEVER via login.call;
			// swallow every failure (429/5xx/network) => no-op, password form untouched.
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
					// Conditional UI FIRST (only if not explicitly unavailable).
					if (caps.conditionalMediation !== false) {
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

	// begin_login via raw fetch (silent config channel, §5.2 step 2). Returns
	// {enabled, modes, state_id?, options?} or null on any failure.
	function beginLogin() {
		return fetch(methodUrl(API.begin_login), {
			method: "POST",
			headers: jsonHeaders(),
			body: "{}",
			credentials: "same-origin",
		})
			.then(function (r) {
				if (!r.ok) return null; // 429/5xx => degrade like enabled:false
				return r.json();
			})
			.then(function (data) { return data ? (data.message || data) : null; })
			.catch(function () { return null; });
	}

	// ------------------------------------------------------- conditional UI (J1)
	function startConditional() {
		var input = C.resolveIdentifierInput(document);
		if (input) {
			// the one-token S6 seam: username -> "username webauthn" (§5.2 step 3)
			var ac = input.getAttribute("autocomplete") || "username";
			if (ac.indexOf("webauthn") === -1) {
				input.setAttribute("autocomplete", (ac + " webauthn").trim());
			}
		} else {
			// input-selector miss (core redesign): skip autocomplete patch AND conditional
			// get(); keep the explicit button. DOM-contract CI is the drift alarm (§5.2 step 3).
			return;
		}
		if (!navigator.credentials || typeof navigator.credentials.get !== "function") return;
		if (!state.login.stateId || !state.login.options) return;

		abortConditional();
		var controller = newAbortController();
		state.conditionalAbort = controller;
		var publicKey;
		try {
			publicKey = C.parseRequestOptionsFromJSON(state.login.options, window.PublicKeyCredential);
		} catch (e) { return; }

		navigator.credentials
			.get({ mediation: "conditional", publicKey: publicKey, signal: controller ? controller.signal : undefined })
			.then(function (cred) {
				state.conditionalAbort = null;
				runVerify(cred, { source: "conditional" });
			})
			.catch(function (err) {
				state.conditionalAbort = null;
				// AbortError is expected (we aborted for a modal get / re-begin) -> ignore.
				if (err && err.name === "AbortError") return;
				// A conditional failure is silent by design (no user gesture yet); a stale
				// challenge re-arms conditional (§5.2.10 case b) via the verify path only.
			});
	}

	function abortConditional() {
		if (state.conditionalAbort) {
			try { state.conditionalAbort.abort(); } catch (e) { /* noop */ }
			state.conditionalAbort = null;
		}
	}

	// ------------------------------------------------------- explicit button (J2)
	function mountButton(caps) {
		if (document.getElementById("passkey-login-btn")) return; // idempotent
		var target = C.resolveButtonMount(document);
		if (!target) return; // no mount => skip button; conditional UI still works

		var btn = document.createElement("button");
		btn.type = "button";
		btn.id = "passkey-login-btn";
		btn.className = "btn btn-sm btn-block btn-login-option btn-passkey-login";
		btn.setAttribute("aria-label", t("Sign in with a passkey"));
		btn.innerHTML =
			'<svg class="icon icon-sm passkey-glyph" aria-hidden="true" focusable="false" ' +
			'viewBox="0 0 24 24"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5c0 1.9 1.06 ' +
			'3.55 2.62 4.4A7 7 0 0 0 4 18v1h9.3a5.5 5.5 0 0 1-.3-1.8c0-1.2.38-2.3 1.02-3.2A5 5 0 ' +
			'0 0 12 2Zm7 9a3 3 0 0 0-1 5.83V22l1 1 1.5-1.5L21 20l-1-1 1-1-1.5-1.17A3 3 0 0 0 19 ' +
			'11Zm0 2a1 1 0 1 1 0 2 1 1 0 0 1 0-2Z"/></svg>' +
			'<span class="passkey-label"></span>';
		// text set via textContent to avoid any interpolation surprises
		btn.querySelector(".passkey-label").textContent = t("Sign in with a passkey");

		// promote-only hint: never gates visibility, may reorder to the top (§5.2 step 4)
		var promote = false;
		try { promote = window.localStorage && localStorage.getItem(HINT_KEY) === "1"; } catch (e) { /* ignore */ }

		if (target.mode === "actions" || target.mode === "providers") {
			// insert as the FIRST alternative-method button (FIDO principle 8, §5.2 step 5)
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
		btn.addEventListener("keydown", function (e) {
			// native <button> already handles Enter/Space; this is belt-and-braces for a11y
			if (e.key === "Enter" || e.key === " ") { /* default action fires click */ }
		});
	}

	function onButtonClick(e) {
		if (e) {
			e.preventDefault();
			e.stopPropagation();
			if (e.stopImmediatePropagation) e.stopImmediatePropagation();
		}
		if (state.busyModal) return;
		abortConditional(); // Chromium rejects overlapping requests (§5.2 step 3)
		modalGet({ source: "button" });
	}

	// ------------------------------------------- modal get() with pre-freshness (J2/J3)
	function modalGet(ctx) {
		// §5.2.10 case a: pre-modal freshness — if the held state is stale, re-begin FIRST,
		// then run the single get() (one gesture, not two failures).
		var proceed = function () {
			if (!state.login.stateId || !state.login.options) {
				announce(t("Passkeys aren't available right now."));
				return;
			}
			var publicKey;
			try {
				publicKey = C.parseRequestOptionsFromJSON(state.login.options, window.PublicKeyCredential);
			} catch (e) {
				announce(t("Couldn't start passkey sign-in."));
				return;
			}
			state.busyModal = true;
			var restore = C.captureFocus(document);
			navigator.credentials
				.get({ publicKey: publicKey })
				.then(function (cred) {
					state.busyModal = false;
					restore();
					runVerify(cred, ctx);
				})
				.catch(function (err) {
					state.busyModal = false;
					restore();
					onCeremonyError(err, ctx);
				});
		};

		if (state.login.needsPreModalRebegin(Date.now())) {
			rebegin().then(function (ok) { if (ok) proceed(); else announce(t("Passkeys aren't available right now.")); });
		} else {
			proceed();
		}
	}

	// re-begin: fetch a fresh state_id + options WITHOUT running any gesture.
	function rebegin() {
		return beginLogin().then(function (cfg) {
			if (cfg && cfg.enabled && cfg.modes && cfg.modes.first_factor && cfg.state_id && cfg.options) {
				state.modes = cfg.modes;
				state.login.adopt(cfg.state_id, cfg.options, Date.now());
				return true;
			}
			return false;
		}, function () { return false; });
	}

	// ------------------------------------------------------ verify (first factor)
	function runVerify(cred, ctx) {
		var attachment = cred && cred.authenticatorAttachment;
		var assertion;
		try {
			assertion = C.authAssertionToJSON(cred);
		} catch (e) {
			announce(t("Couldn't read the passkey response."));
			return;
		}
		var payload = { state_id: state.login.stateId, credential: JSON.stringify(assertion) };

		frappeCall(API.verify_login, payload, composedHandlers({
			on401: function (data) { handleFirstFactor401(data, ctx, attachment); },
			onSuccess: function (data) {
				rememberHint();
				postLoginUpsell(attachment, data);
				// core's 200 handler (base) runs first for the redirect/splash; nothing to do
			},
		}));
	}

	function handleFirstFactor401(data, ctx, attachment) {
		var kind = C.mapServerExcType(data && data.exc_type);
		if (kind === "ceremony_expired") {
			// §5.2.10 case c: re-begin + ONE fresh ceremony, at most once. NEVER re-POST.
			if (state.login.canRearm()) {
				state.login.markRearm();
				rebegin().then(function (ok) {
					if (!ok) { neutralFail(); return; }
					if (ctx.source === "button") {
						modalGet(ctx);
					} else {
						startConditional(); // silent re-arm of conditional UI
					}
				});
			} else {
				neutralFail();
			}
			return;
		}
		if (kind === "unknown_credential") {
			signalUnknownCredential();
			announce(t("That passkey isn't registered here."));
			neutralInline(t("That passkey isn't registered here — sign in another way."));
			rearmAfterVisibleFailure(ctx);
			return;
		}
		if (kind === "uv_setup_required") {
			openUvSetup(data && data.setup_id);
			return;
		}
		// unknown typed error / plain 401 -> re-arm once so the user is never dead-ended
		neutralFail();
		rearmAfterVisibleFailure(ctx);
	}

	// after any user-visible failure that consumed the state, re-begin once to re-arm
	// conditional UI + the button (bounded; never a loop) — §5.2.10 re-arm rule.
	function rearmAfterVisibleFailure(ctx) {
		if (!state.login.canRearm()) return;
		state.login.markRearm();
		rebegin().then(function (ok) {
			if (ok && ctx && ctx.source === "conditional") startConditional();
		});
	}

	// ---------------------------------------------- uv-setup step-up (§3.4)
	function openUvSetup(setupId) {
		if (!setupId) { neutralFail(); return; }
		var restore = C.captureFocus(document);
		var dlg = buildDialog({
			titleText: t("Finish setting up this passkey"),
			bodyHtml:
				'<p>' + escapeHtml(t("Confirm your password once to finish setting up this passkey.")) + '</p>' +
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
						onSuccess: function () { rememberHint(); close(); /* base 200 redirects */ },
					})
				);
			},
			onClose: restore,
		});
		openDialog(dlg);
		var pwdInput = dlg.root.querySelector("#passkey-uv-pwd");
		if (pwdInput) pwdInput.focus();
	}

	// ----------------------------------------- second factor interception (J4)
	function installSecondFactorInterception() {
		if (state.sfInterceptor) return;
		state.sfInterceptor = function (event) {
			var form = event.target && event.target.closest && event.target.closest(".form-login");
			if (!form) return; // not the login form
			// Degrade rule (verbatim, §5.2 step 7): ANY JS error => remove the listener and
			// let the native submit proceed. Never deaden the login page.
			try {
				var usr = valueOf("#login_email");
				var pwd = valueOf("#login_password");
				if (!usr || !pwd) return; // let core validate empty fields natively
				event.preventDefault();
				event.stopImmediatePropagation();
				loginWithPassword(usr, pwd);
			} catch (e) {
				removeSecondFactorInterception();
				// do not preventDefault on this pass: let the browser submit natively
			}
		};
		document.addEventListener("submit", state.sfInterceptor, true); // capture phase
	}

	function removeSecondFactorInterception() {
		if (state.sfInterceptor) {
			document.removeEventListener("submit", state.sfInterceptor, true);
			state.sfInterceptor = null;
		}
	}

	function loginWithPassword(usr, pwd) {
		setStatus(t("Verifying..."));
		frappeCall(API.login_with_password, { usr: usr, pwd: pwd }, composedHandlers({
			// 200 wrapper (below) already pre-inspects verification.method === "Passkey".
			on401: function (data) {
				// mode-off or bad-credential -> let core's painter show it
				coreDelegate401(data);
			},
			onSuccess: function (data) {
				if (data && data.verification && data.verification.method === "Passkey") {
					driveSecondFactor(data);
				}
				// else: base 200 handler already handled Logged In / OTP App / SMS / Email
			},
		}));
	}

	// leg 2: modal get() with the server's RequestOptionsJSON (UV discouraged, §3.7) ->
	// verify_second_factor. Re-arm (fresh state in the 401 body) + OTP fallback per §6.3.
	function driveSecondFactor(env) {
		var verification = env.verification || {};
		var tmpId = env.tmp_id;
		var options = verification.options;
		var fallbackOtp = verification.fallback && verification.fallback.otp;
		runSecondFactorCeremony(tmpId, options, fallbackOtp);
	}

	function runSecondFactorCeremony(stateId, options, fallbackOtp) {
		var restore = C.captureFocus(document);
		var publicKey;
		try {
			publicKey = C.parseRequestOptionsFromJSON(options, window.PublicKeyCredential);
		} catch (e) { announce(t("Couldn't start passkey verification.")); restore(); return; }

		var dlg = buildDialog({
			titleText: t("Confirm it's you"),
			bodyHtml:
				'<p>' + escapeHtml(t("Use your passkey to finish signing in.")) + '</p>' +
				'<p class="passkey-dialog-error" role="alert"></p>',
			primaryText: t("Use a passkey"),
			secondaryText: fallbackOtp ? t("Use a verification code instead") : null,
			onPrimary: function (root, close, ctxState) {
				announce(t("Waiting for your passkey."));
				navigator.credentials.get({ publicKey: publicKey })
					.then(function (cred) {
						var assertion = C.authAssertionToJSON(cred);
						frappeCall(API.verify_second_factor,
							{ state_id: ctxState.stateId, credential: JSON.stringify(assertion) },
							composedHandlers({
								on401: function (d) {
									var k = C.mapServerExcType(d && d.exc_type);
									if (k === "ceremony_expired") {
										// server re-armed: fresh state in the 401 body
										var fresh = reArmedFrom(d);
										if (fresh) {
											ctxState.stateId = fresh.stateId;
											try {
												publicKey = C.parseRequestOptionsFromJSON(fresh.options, window.PublicKeyCredential);
											} catch (e2) { /* keep old */ }
											setDialogError(root, t("That didn't work — try your passkey again."));
										} else {
											close(); coreDelegate401(d);
										}
									} else {
										setDialogError(root, t("That passkey couldn't be verified — try again."));
									}
								},
								onSuccess: function () { rememberHint(); close(); /* base 200 redirects */ },
							})
						);
					})
					.catch(function (err) {
						var m = C.mapDomException(err);
						setDialogError(root, t(m.messageKey));
						announce(t(m.messageKey));
					});
			},
			onSecondary: fallbackOtp ? function (root, close, ctxState) {
				// "Use a verification code instead" -> fallback_to_otp -> core OTP UI natively
				frappeCall(API.fallback_to_otp, { state_id: ctxState.stateId },
					composedHandlers({
						on401: function (d) { close(); coreDelegate401(d); },
						// core's 200 handler paints the OTP form (verification.method OTP/SMS/Email)
						onSuccess: function () { close(); },
					})
				);
			} : null,
			onClose: restore,
			ctxState: { stateId: stateId },
		});
		openDialog(dlg);
	}

	function reArmedFrom(data) {
		if (!data) return null;
		var sid = data.state_id || data.tmp_id ||
			(data.verification && data.verification.tmp_id);
		var opts = data.verification && data.verification.options;
		if (sid && opts) return { stateId: sid, options: opts };
		return null;
	}

	// ------------------------------------------------------- signals (fire-and-forget)
	function signalUnknownCredential() {
		if (!window.PublicKeyCredential ||
			typeof window.PublicKeyCredential.signalUnknownCredential !== "function") return;
		// We have no rpId/credentialId to pass safely here without leaking; the server-side
		// UnknownCredential is the authoritative feed. Post-login signalAllAcceptedCredentials
		// is driven from get_signal_data (below). Guard the whole thing fire-and-forget.
		try {
			var p = window.PublicKeyCredential.signalUnknownCredential({});
			if (p && typeof p.catch === "function") p.catch(noop); // Safari 26 never-settles
		} catch (e) { /* Firefox absent, etc. */ }
	}

	function postLoginUpsell(attachment, data) {
		// §5.2 step 8: cross-device assertion + local UVPAA => flag "add a passkey to this
		// device" for the post-login surface. We stash a hint the desk/portal bundle reads.
		try {
			if (attachment === "cross-platform" && window.localStorage) {
				localStorage.setItem("passkey_upsell_add_local", "1");
			}
		} catch (e) { /* ignore */ }
		// signalAllAcceptedCredentials is best-effort; the desk bundle refreshes it in-session.
		void data;
	}

	// ---------------------------------------------------- frappe.call plumbing
	// Composed handler set: {...login.login_handlers, 200: wrapped, 401: app, 429: app}
	// so core paints Logged In / OTP / Password Reset natively while typed passkey errors
	// (exc_type) route to us and unknown types delegate back to core's painter (§5.2 step 6).
	function composedHandlers(app) {
		var base = (window.login && window.login.login_handlers) || {};
		var merged = {};
		for (var code in base) { if (Object.prototype.hasOwnProperty.call(base, code)) merged[code] = base[code]; }

		var base200 = base[200];
		merged[200] = function (data /*, textStatus, xhr */) {
			// pre-inspect for the Passkey second-factor branch core doesn't know yet
			if (data && data.verification && data.verification.method === "Passkey") {
				if (app.onSuccess) app.onSuccess(data);
				return; // do NOT let base paint an unknown verification.method
			}
			if (base200) { try { base200(data); } catch (e) { /* core handler */ } }
			if (app.onSuccess) app.onSuccess(data);
		};

		merged[401] = function (xhr /*, textStatus, errorThrown */) {
			var data = (xhr && xhr.responseJSON) || {};
			var kind = C.mapServerExcType(data.exc_type);
			if (kind !== "unknown" && app.on401) {
				app.on401(data);
			} else if (base[401]) {
				base[401](xhr, data); // core's "Invalid credentials" painter
			}
		};

		merged[429] = function (xhr) {
			// degrade rules (§5.2 steps 2/10): show core's throttle copy, never crash
			if (base[429]) base[429](xhr, (xhr && xhr.responseJSON) || {});
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

	function frappeCall(method, args, statusCode) {
		if (window.frappe && typeof window.frappe.call === "function") {
			return window.frappe.call({
				method: method,
				type: "POST",
				args: args,
				freeze: true,
				statusCode: statusCode,
			});
		}
		// last-ditch raw fetch (no jQuery/frappe.call) — drives the same status handlers
		return rawCall(methodUrl(method), args, statusCode);
	}

	function rawCall(url, args, statusCode) {
		return fetch(url, {
			method: "POST",
			headers: jsonHeaders(),
			body: JSON.stringify(args || {}),
			credentials: "same-origin",
		}).then(function (r) {
			return r.json().catch(function () { return {}; }).then(function (data) {
				var h = statusCode && statusCode[r.status];
				if (r.status === 200) { if (h) h(data); }
				else if (h) h({ responseJSON: data, status: r.status });
			});
		});
	}

	// --------------------------------------------------------------- dialog a11y
	// role=dialog + aria-labelledby, focus trap, Esc = dismiss, focus returns to invoker.
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
		cancel.className = "btn btn-sm btn-link btn-block passkey-dialog-cancel";
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
		// initial focus on the primary action (§5.5) unless the caller focuses an input
		setTimeout(function () { if (dlg.primary) dlg.primary.focus(); }, 0);
	}

	function setDialogError(root, msg) {
		var el = root.querySelector(".passkey-dialog-error");
		if (el) el.textContent = msg;
		announce(msg);
	}

	// ----------------------------------------------------------- error paths / UX
	function onCeremonyError(err, ctx) {
		var m = C.mapDomException(err);
		neutralInline(t(m.messageKey));
		announce(t(m.messageKey));
		// user cancel/timeout: untouched form + one neutral message, then re-arm once so the
		// user is never dead-ended (§5.2 step 10).
		rearmAfterVisibleFailure(ctx);
	}

	function neutralFail() {
		neutralInline(t("Couldn't use a passkey — sign in another way."));
		announce(t("Couldn't use a passkey — sign in another way."));
	}

	function neutralInline(msg) {
		// paint into core's own error banner slot when present; never blocks the form
		var banner = document.querySelector("section .login-error-banner span, .login-error-banner span");
		if (banner) {
			var wrap = banner.closest ? banner.closest(".login-error-banner") : null;
			banner.textContent = msg;
			if (wrap && wrap.style) wrap.style.display = "flex";
		}
	}

	function rebeginAndRearm() {
		rebegin().then(function (ok) { if (ok) startConditional(); });
	}

	// -------------------------------------------------------------- small utils
	function setStatus(msg) { announce(msg); }
	function announce(msg) { C.announce(document, msg); }
	function rememberHint() { try { if (window.localStorage) localStorage.setItem(HINT_KEY, "1"); } catch (e) { /* ignore */ } }
	function removeSelf() { removeSecondFactorInterception(); abortConditional(); var b = document.getElementById("passkey-login-btn"); if (b && b.parentNode) b.parentNode.removeChild(b); }
	function valueOf(sel) { var el = document.querySelector(sel); return el ? (el.value || "").trim() : ""; }
	function methodUrl(method) { return "/api/method/" + method; }
	function jsonHeaders() {
		var h = { "Content-Type": "application/json", Accept: "application/json" };
		var token = window.frappe && (window.frappe.csrf_token || (window.frappe.session && window.frappe.session.csrf_token));
		if (token) h["X-Frappe-CSRF-Token"] = token; // guests are CSRF-exempt (§3); harmless if sent
		return h;
	}
	function newAbortController() { return (typeof AbortController === "function") ? new AbortController() : null; }
	function escapeHtml(s) {
		return String(s).replace(/[&<>"']/g, function (c) {
			return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
		});
	}
	function noop() {}

	// expose a tiny surface for the DOM-contract Cypress job (§12.4) to assert against
	window.frappe = window.frappe || {};
	window.frappe._passkey_login = { boot: boot, _state: state, API: API };
})();
