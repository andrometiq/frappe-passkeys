// passkey_login.bundle.js — passkey login-page bundle (conditional UI, explicit
// button, cross-device, password->passkey second factor, uv-setup step-up).
//
// Delivered via update_website_context -> context.web_include_js on /login when any mode is
// enabled. Loaded AFTER passkey_common.bundle.js (which sets frappe.passkeys_common) and
// AFTER frappe-web.bundle.js (which defines window.__). Owns its own lifecycle: boots once on
// login_rendered, with a DOMContentLoaded fallback and an idempotent guard. Any JS
// failure degrades to the untouched core password form — the page is never deadened.
//
// The whole file is an IIFE (classic script) so it needs no bundler module resolution and is
// `node --check`-able as-is. Server contracts are pinned wire shapes.
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
	var HINT_KEY = "passkey_used_here"; // localStorage promote-only hint
	var STATUS_ID = "passkey-login-status"; // the app-owned visible staged-status element
	var SLOW_MS = 4000; // slow-connection "still working" escalation while verifying
	var BOOTED = false;

	// bundle-scoped runtime state
	var state = {
		modes: { first_factor: false, second_factor: false },
		login: new C.CeremonyState({ ttlMs: 300000 }),
		status: new C.LoginStatus(), // the visible staged-status machine (A5/A6/C1)
		slowTimer: null, // setTimeout handle for the slow-connection escalation
		conditionalAbort: null, // AbortController for the pending conditional get()
		conditionalEnabled: false, // capability decision for this login-page surface
		sfInterceptor: null, // the document capture-phase submit listener
		busyModal: false, // a modal get()/create() is in flight
	};

	// -------------------------------------------------------------- boot glue
	function boot() {
		if (BOOTED) return; // idempotent injection guard (login_rendered is one-shot)
		BOOTED = true;
		C.ensureLiveRegion(document);
		// merge our own guest translation catalog (REQUIRED on v15/v16), then start.
		loadAppTranslations()
			.catch(noop) // English fallback is acceptable; never block boot
			.then(start);
	}

	// listen once + DOMContentLoaded fallback (the event is one-shot)
	document.addEventListener("login_rendered", boot, { once: true });
	window.addEventListener("pageshow", onPageShow);
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", function () {
			// only if login_rendered never fired (e.g. custom template)
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

	// ---------------------------------------------------------- i18n loader
	// Fetch the app guest translations endpoint once, memoize, MERGE (never clobber) into
	// frappe._messages. On develop, also await frappe._translations_loaded so the
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
					ensureStatusEl(); // app-owned visible status (never core's develop-only banner)
					// Conditional UI FIRST (only if not explicitly unavailable).
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

	// begin_login via raw fetch (silent config channel). Returns
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

	// ------------------------------------------------------- conditional UI
	function startConditional() {
		if (!state.conditionalEnabled) return;
		var input = C.resolveIdentifierInput(document);
		if (input) {
			// the one-token seam: username -> "username webauthn"
			var ac = input.getAttribute("autocomplete") || "username";
			if (ac.indexOf("webauthn") === -1) {
				input.setAttribute("autocomplete", (ac + " webauthn").trim());
			}
		} else {
			// input-selector miss (core redesign): skip autocomplete patch AND conditional
			// get(); keep the explicit button. DOM-contract CI is the drift alarm.
			return;
		}
		if (!navigator.credentials || typeof navigator.credentials.get !== "function") return;
		var stateId = state.login.stateId;
		var options = state.login.options;
		if (!stateId || !options) return;

		abortConditional();
		var controller = newAbortController();
		state.conditionalAbort = controller;
		var publicKey;
		try {
			publicKey = C.parseRequestOptionsFromJSON(options, window.PublicKeyCredential);
		} catch (e) { state.login.markSpent(stateId); return; }

		navigator.credentials
			.get({ mediation: "conditional", publicKey: publicKey, signal: controller ? controller.signal : undefined })
			.then(function (cred) {
				state.conditionalAbort = null;
				runVerify(cred, { source: "conditional" }, stateId);
			})
			.catch(function (err) {
				state.conditionalAbort = null;
				// AbortError is expected (we aborted for a modal get / re-begin) -> ignore.
				if (err && err.name === "AbortError") return;
				state.login.markSpent(stateId);
				// A conditional failure is silent by design (no user gesture yet); a stale
				// challenge re-arms conditional via the verify path only.
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
		if (document.getElementById("passkey-login-btn")) return; // idempotent
		var target = C.resolveButtonMount(document);
		if (!target) return; // no mount => skip button; conditional UI still works

		var btn = document.createElement("button");
		btn.type = "button";
		btn.id = "passkey-login-btn";
		btn.className = "btn btn-sm btn-block btn-login-option btn-passkey-login";
		btn.setAttribute("aria-label", t("Sign in with a passkey"));
		// App-shipped inline key glyph (C.iconSvg) — identical on every Frappe version,
		// unlike the #icon-key sprite ref, which is blank on v15 (no web_include_icons).
		// .passkey-glyph is a bare test hook; core .icon/.icon-sm size it.
		btn.innerHTML =
			C.iconSvg("key", "icon icon-sm passkey-glyph") +
			'<span class="passkey-label"></span>';
		// text set via textContent to avoid any interpolation surprises
		btn.querySelector(".passkey-label").textContent = t("Sign in with a passkey");

		// promote-only hint: never gates visibility, may reorder to the top
		var promote = false;
		try { promote = window.localStorage && localStorage.getItem(HINT_KEY) === "1"; } catch (e) { /* ignore */ }

		if (target.mode === "actions" || target.mode === "providers") {
			// insert as the FIRST alternative-method button (FIDO principle 8)
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
		abortConditional(); // Chromium rejects overlapping requests
		modalGet({ source: "button" });
	}

	// ------------------------------------------- modal get() with pre-freshness
	function modalGet(ctx) {
		// pre-modal liveness — if the held state is spent or stale, re-begin FIRST,
		// then run the single get() (one gesture, not two failures).
		var proceed = function () {
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
			var restore = C.captureFocus(document);
			// Stage 1 — the authenticator/browser sheet is up (before/around get()).
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

		// Stage 2 — server round-trip. Arm the slow-connection escalation on a timer.
		applyLoginStatus("verifying");
		armSlowTimer();

		// Terminal cleanup for the verify round-trip. The named handlers below only resolve
		// the surface on 200 (onSuccessEarly) and the TYPED passkey 401s (on401). A plain 401
		// (core "Invalid credentials" painter), a 417/429/5xx, or a transport/network failure
		// would otherwise leave the slow timer armed and the surface stuck on "Verifying…" —
		// escalating to the slow-connection copy and never resolving — while core paints its
		// own banner, so the two surfaces disagree. `claimed` marks the outcomes an app handler
		// already owns: success, and the typed-401 paths that manage their own lifecycle
		// (including the transparent ceremony_expired re-arm, which legitimately sits in
		// "verifying" across an async rebegin — a blanket finalizer would flash "failed" over
		// it). For EVERY other outcome the finalizer runs exactly once: it clears the timer and,
		// only if still stuck mid-progress, downgrades to the generic "failed" route-out. The
		// LoginStatus machine rejects any transition out of a terminal state, so this can never
		// clobber a success/removed/cancelled/… paint (belt-and-braces with the state guard).
		var claimed = false;
		var settled = false;
		function finishVerify() {
			if (settled) return; // idempotent — a promise settles once, but guard regardless
			settled = true;
			if (claimed) return; // an app handler already owns (and painted) this outcome
			clearSlowTimer();
			var s = state.status.state;
			if (s === "verifying" || s === "verifying_slow" || s === "waiting") {
				applyLoginStatus("failed");
			}
		}

		var call = frappeCall(API.verify_login, payload, composedHandlers({
			on401: function (data) { claimed = true; clearSlowTimer(); handleFirstFactor401(data, ctx, attachment, cred); },
			// Stage 3 — the resolved "You're in" beat, painted BEFORE core's redirect runs
			// (onSuccessEarly is invoked ahead of base's 200 handler; see composedHandlers).
			onSuccessEarly: function () { claimed = true; clearSlowTimer(); applyLoginStatus("success"); },
			onSuccess: function (data) {
				rememberHint();
				postLoginUpsell(attachment, data);
			},
		}));

		// The single always-style seam: frappe.call (and the rawCall fallback) both return a
		// thenable that settles AFTER the statusCode handler on every outcome — resolve OR
		// reject/transport error. login.js itself relies on this contract (login.call(...).then).
		// Pass finishVerify to both slots so it fires once regardless of settle direction.
		if (call && typeof call.then === "function") {
			call.then(finishVerify, finishVerify);
		}
	}

	function handleFirstFactor401(data, ctx, attachment, cred) {
		var kind = C.mapServerExcType(data && data.exc_type);
		if (kind === "ceremony_expired") {
			// re-begin + ONE fresh ceremony, at most once. NEVER re-POST.
			if (state.login.canRearm()) {
				rebegin().then(function (ok) {
					if (!ok) { neutralFail(); return; }
					state.login.markRearm();
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
			// A5 — the passkey is on the device but the server no longer has it (removed/
			// stale). Give it a DISTINCT visible state instead of doing nothing, and (F1)
			// tell the provider so it prunes the dead passkey from the device.
			signalUnknownCredential(cred);
			applyLoginStatus(C.loginStatusForServerKind(kind)); // -> "removed"
			rearmAfterVisibleFailure();
			return;
		}
		if (kind === "uv_setup_required") {
			applyLoginStatus("idle"); // hand the surface to the password step-up dialog
			openUvSetup(data && data.setup_id);
			return;
		}
		// unknown typed error / plain 401 -> re-arm once so the user is never dead-ended
		neutralFail();
		rearmAfterVisibleFailure();
	}

	// after any user-visible failure that spent the state, re-begin once to re-arm
	// conditional UI + the button (bounded; never a loop).
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

	// ----------------------------------------- second factor interception
	function installSecondFactorInterception() {
		if (state.sfInterceptor) return;
		state.sfInterceptor = function (event) {
			var form = event.target && event.target.closest && event.target.closest(".form-login");
			if (!form) return; // not the login form
			// Degrade rule (verbatim): ANY JS error => remove the listener and
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
		setStatus(t("Verifying…"));
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

	// leg 2: modal get() with the server's RequestOptionsJSON (UV discouraged) ->
	// verify_second_factor. Re-arm (fresh state in the 401 body) + OTP fallback.
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

	// Unsupported WebAuthn is a terminal routing decision, not a ceremony error. If the
	// server authorized OTP fallback, make that the primary action immediately. Otherwise
	// show an explicit recovery state with a route back to the login form.
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
				: function (root, close) {
					void root;
					close();
					if (window.location && typeof window.location.reload === "function") window.location.reload();
				},
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
			announce(t("Couldn't open verification-code sign-in. Return to sign in or contact your administrator."));
		}
		if (call && typeof call.then === "function") call.then(finish, finish);
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
					var handled = false;
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
						var assertion = C.authAssertionToJSON(cred);
							var call = frappeCall(API.verify_second_factor,
								{ state_id: ctxState.stateId, credential: JSON.stringify(assertion) },
								composedHandlers({
										on401: function (d) {
											handled = true;
											ctxState.ceremonyPending = false;
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
										on429: function () {
											handled = true;
											ctxState.ceremonyPending = false;
											setDialogError(root, t("Too many attempts. Wait a moment, then try again."));
										},
										onSuccess: function () { handled = true; rememberHint(); close(); /* base 200 redirects */ },
									})
								);
								if (call && typeof call.then === "function") {
									return call.then(function () {
										if (handled) return;
										ctxState.ceremonyPending = false;
										setDialogError(root, t("That passkey couldn't be verified — try again."));
									}, function (err) {
										if (handled) return;
										ctxState.ceremonyPending = false;
										setDialogError(root, t("That passkey couldn't be verified — try again."));
										announce(t("That passkey couldn't be verified — try again."));
										void err;
									});
								}
								ctxState.ceremonyPending = false;
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
						announce(t(m.messageKey));
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

	function reArmedFrom(data) {
		if (!data) return null;
		var sid = data.state_id || data.tmp_id ||
			(data.verification && data.verification.tmp_id);
		var opts = data.verification && data.verification.options;
		if (sid && opts) return { stateId: sid, options: opts };
		return null;
	}

	// ------------------------------------------------------- signals (fire-and-forget)
	// F1: pass the REAL {rpId, credentialId} for the credential the server just rejected, so
	// the provider (Chrome/GPM) actually prunes the dead passkey from the device. The old
	// call passed {} — per spec that rejects with TypeError and prunes nothing. The client
	// already holds the asserted rawId (via cred) and the rpId. buildUnknownCredentialSignal
	// guards the honest cases (skips when no userHandle, so a live credential is never hidden).
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

	// The Relying Party ID for signal calls: the begin_login options carry it; else the
	// boot payload; else the current host (all resolve to the same registrable domain).
	function resolveRpId() {
		var opts = state.login && state.login.options;
		if (opts && opts.rpId) return opts.rpId;
		var b = window.frappe && window.frappe.boot && window.frappe.boot.passkeys;
		if (b && b.rp_id) return b.rp_id;
		return (window.location && window.location.hostname) || null;
	}

	function postLoginUpsell(attachment, data) {
		// cross-device assertion + local UVPAA => flag "add a passkey to this
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
	// (exc_type) route to us and unknown types delegate back to core's painter.
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
			// onSuccessEarly runs BEFORE core's 200 handler so the "You're in" resolved beat
			// is painted before base200 kicks off the redirect (FIDO P4: show the result).
			if (app.onSuccessEarly) { try { app.onSuccessEarly(data); } catch (e) { /* never block core */ } }
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
			// degrade rules: show core's throttle copy, never crash
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
		// Initial focus belongs on the primary action unless a caller has already
		// placed it on a more useful control (the UV-repair password input does so
		// immediately after openDialog). Do not let this deferred callback steal
		// focus after the first typed character.
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
	function onCeremonyError(err, ctx) {
		var m = C.mapDomException(err);
		// user cancel/timeout (indistinguishable) / not-supported / etc. — a distinct visible
		// state + the untouched form, then re-arm once so the user is never dead-ended.
		applyLoginStatus(C.loginStatusForDomCode(m.code));
		rearmAfterVisibleFailure(ctx);
	}

	function neutralFail() {
		applyLoginStatus("failed");
	}

	// ------------------------------------------ visible staged status surface (A5/A6/C1)
	// The app ships its OWN status element on the login page — NEVER core's
	// .login-error-banner, which exists only on develop (that develop-only coupling is
	// exactly why a removed passkey showed nothing on v15). Renders identically on
	// v15/v16/develop website login pages.
	function ensureStatusEl() {
		if (document.getElementById(STATUS_ID)) return;
		var el = document.createElement("div");
		el.id = STATUS_ID;
		el.className = "passkey-status";
		el.hidden = true;
		el.innerHTML =
			'<span class="passkey-status__icon" aria-hidden="true"></span>' +
			'<span class="passkey-status__text"></span>';
		// Place it just above the login card's action group (or the form) so it reads
		// prominently; a miss still leaves the aria-live region covering AT users.
		var target = C.resolveButtonMount(document);
		if (target && target.mount && target.mount.parentNode) {
			target.mount.parentNode.insertBefore(el, target.mount);
		} else if (target && target.mount) {
			target.mount.insertBefore(el, target.mount.firstChild);
		} else {
			var form = document.querySelector(".form-login");
			if (form && form.parentNode) form.parentNode.insertBefore(el, form);
			else (document.body || document.documentElement).appendChild(el);
		}
	}

	function statusEl() { return document.getElementById(STATUS_ID); }

	// The SINGLE chokepoint: advance the pure machine, paint the visible element, and
	// announce the SAME text to the aria-live region — one source of truth feeding both,
	// so the sighted + screen-reader states stay in lockstep (A6).
	function applyLoginStatus(stateName) {
		if (stateName !== "verifying") clearSlowTimer(); // any resolution stops the escalation
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
				if (textEl) textEl.textContent = text;
			}
		}
		if (view.visible && text) announce(text); // lockstep aria-live announcement
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
	function setStatus(msg) { announce(msg); }
	function announce(msg) { C.announce(document, msg); }
	function rememberHint() { try { if (window.localStorage) localStorage.setItem(HINT_KEY, "1"); } catch (e) { /* ignore */ } }
	function removeSelf() { removeSecondFactorInterception(); abortConditional(); clearSlowTimer(); var s = document.getElementById(STATUS_ID); if (s && s.parentNode) s.parentNode.removeChild(s); var b = document.getElementById("passkey-login-btn"); if (b && b.parentNode) b.parentNode.removeChild(b); }
	function valueOf(sel) { var el = document.querySelector(sel); return el ? (el.value || "").trim() : ""; }
	function methodUrl(method) { return "/api/method/" + method; }
	function jsonHeaders() {
		var h = { "Content-Type": "application/json", Accept: "application/json" };
		var token = window.frappe && (window.frappe.csrf_token || (window.frappe.session && window.frappe.session.csrf_token));
		if (token) h["X-Frappe-CSRF-Token"] = token; // guests are CSRF-exempt; harmless if sent
		return h;
	}
	function newAbortController() { return (typeof AbortController === "function") ? new AbortController() : null; }
	function escapeHtml(s) {
		return String(s).replace(/[&<>"']/g, function (c) {
			return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
		});
	}
	function noop() {}

	// expose a tiny surface for the DOM-contract Cypress job to assert against
	window.frappe = window.frappe || {};
	window.frappe._passkey_login = { boot: boot, _state: state, API: API, applyLoginStatus: applyLoginStatus };

	// Node-only test seam (UMD-lite, mirrors passkey_common.bundle.js / passkey_confirm.bundle.js): expose
	// the verify round-trip + status machine so `node --test` can pin the terminal-cleanup
	// behaviour without a bench/jsdom. No-op in the browser — `module` is undefined there.
	if (typeof module === "object" && module.exports) {
		module.exports = {
			state: state, runVerify: runVerify, applyLoginStatus: applyLoginStatus,
			armSlowTimer: armSlowTimer, clearSlowTimer: clearSlowTimer, API: API,
			onButtonClick: onButtonClick, modalGet: modalGet, rebegin: rebegin,
			onPageShow: onPageShow,
			secondFactorWebAuthnAvailable: secondFactorWebAuthnAvailable,
			showSecondFactorUnavailable: showSecondFactorUnavailable,
		};
	}
})();
