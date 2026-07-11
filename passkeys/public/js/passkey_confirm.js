// passkey_confirm.js — the client half of the action-confirmation
// ("passkey signing") primitive. Publishes the public JS API other Desk / portal
// apps call to require a fresh passkey confirmation for a sensitive action.
//
// Public API:
//   const grant = await frappe.passkeys.confirm("myapp.release_payment", {payment_id});
//   await frappe.passkeys.call("myapp.api.release_payment", {payment_id});
// Core destination namespace: frappe.ui.passkey.* (aliased here for forward-compat).
//
// This file is the browser/frappe-bound wiring: raw fetch (CSRF + credentials),
// the WebAuthn L3 gesture, and the frappe.ui.Dialog confirmation UI + a11y. ALL
// protocol/state-machine logic (begin -> gesture -> verify -> grant, the 401
// retry / verbatim payload_fingerprint echo, concurrency dedupe, the
// typed rejection taxonomy) lives in passkey_common.js::createConfirmEngine so
// it is unit-testable under `node --test` without a bench. JS NEVER computes a
// payload hash — begin_confirmation is handed raw params, or echoes back a
// server-issued payload_fingerprint verbatim.
//
// Loaded as an app_include_js entry AFTER passkey_common.js (which sets the
// frappe.passkeys_common global this file reads).
//
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	if (!C) {
		// common lib missing — fail safe: expose a stub that rejects clearly
		// rather than throwing at load time on every Desk page.
		return installStub();
	}

	var t = C.t;

	// ---------------------------------------------------------------- transport
	function methodUrl(method) { return "/api/method/" + method; }

	function jsonHeaders(extra) {
		var h = { "Content-Type": "application/json", Accept: "application/json" };
		var f = window.frappe;
		var token = f && (f.csrf_token || (f.session && f.session.csrf_token));
		if (token) h["X-Frappe-CSRF-Token"] = token; // authed POSTs require CSRF
		if (extra) for (var k in extra) if (extra.hasOwnProperty(k)) h[k] = extra[k];
		return h;
	}

	// Raw fetch so we own the 401 body (the retry contract) and can attach the
	// grant header on retry — bypasses frappe's global error painter.
	// Resolves to {ok, status, body} for ANY HTTP status; rejects only on a
	// transport-level failure (offline / DNS), which the engine maps to `network`.
	function post(method, body, headers) {
		return fetch(methodUrl(method), {
			method: "POST",
			headers: jsonHeaders(headers),
			credentials: "same-origin",
			body: JSON.stringify(body || {}),
		}).then(function (resp) {
			return resp
				.json()
				.catch(function () { return null; })
				.then(function (json) {
					return { ok: resp.ok, status: resp.status, body: json };
				});
		});
	}

	// ------------------------------------------------------------------ gesture
	// Parse the L3 RequestOptionsJSON, run a MODAL get() (UV is wire-required by
	// the server options), serialize the assertion to AuthenticationJSON.
	function runGesture(optionsJSON) {
		if (!navigator.credentials || typeof navigator.credentials.get !== "function") {
			var e = new Error("not supported");
			e.name = "NotSupportedError";
			return Promise.reject(e);
		}
		var publicKey = C.parseRequestOptionsFromJSON(optionsJSON);
		// Modal mediation is the default for get() — no `mediation` field, no
		// conditional autofill (confirmation is an explicit, foreground gesture).
		return navigator.credentials
			.get({ publicKey: publicKey })
			.then(function (cred) {
				if (!cred) {
					var err = new Error("no credential");
					err.name = "NotAllowedError";
					throw err;
				}
				return C.authAssertionToJSON(cred);
			});
	}

	// ------------------------------------------------------------------ dialog
	// A frappe.ui.Dialog-backed confirmation UI. Returns the `ui` controller the
	// engine drives (chooseMethod / collectPassword / announce / busy / done).
	// One dialog instance per ceremony; the engine guarantees only one is live
	// at a time (concurrency dedupe), so we mint a fresh controller each run.
	function makeDialogUI() {
		var dialog = null;
		var restoreFocus = C.captureFocus(document);
		var liveRegionSeeded = false;

		function ensureDialog(opts) {
			if (dialog) return dialog;
			var Dialog = window.frappe && window.frappe.ui && window.frappe.ui.Dialog;
			var title = t("Confirm it's you");
			var d;
			if (Dialog) {
				d = new Dialog({ title: title, size: "small" });
			} else {
				// Extremely defensive: frappe.ui.Dialog should always be present
				// in Desk/portal. If not, degrade to a minimal API-compatible shim.
				d = minimalDialog(title);
			}
			dialog = d;
			return d;
		}

		function bodyEl() {
			// frappe.ui.Dialog exposes $body (jQuery) and .body (DOM).
			if (dialog.$body && dialog.$body.get) return dialog.$body.get(0);
			return dialog.body || (dialog.$wrapper && dialog.$wrapper.get && dialog.$wrapper.get(0));
		}

		function setContent(html) {
			if (dialog.$body && dialog.$body.html) { dialog.$body.html(html); return; }
			var el = bodyEl();
			if (el) el.innerHTML = html;
		}

		function seedA11y() {
			var el = bodyEl();
			if (!el) return;
			if (!liveRegionSeeded) {
				var lr = C.ensureLiveRegion(el.ownerDocument || document);
				// frappe.ui.Dialog already sets role="dialog" + aria-labelledby +
				// focus trap + Esc; we only add the async live region + labels.
				liveRegionSeeded = true;
				void lr;
			}
		}

		function show() {
			if (dialog.show) dialog.show();
			else if (dialog.$wrapper && dialog.$wrapper.modal) dialog.$wrapper.modal("show");
			seedA11y();
		}

		function esc(s) {
			return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
				return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
			});
		}

		function actionLabel(action) {
			// action is a dotted method path (e.g. "myapp.release_payment").
			var tail = String(action || "").split(".").pop() || String(action || "");
			return tail.replace(/_/g, " ");
		}

		var controller = {
			// Show the passkey confirmation UI; resolve with the chosen method.
			chooseMethod: function (opts) {
				return new Promise(function (resolve, reject) {
					ensureDialog(opts);
					var actName = esc(actionLabel(opts.action));
					var lines = [
						'<div class="passkey-confirm" role="group" aria-label="' +
							esc(t("Confirm this action with a passkey")) + '">',
						'<p class="passkey-confirm-lead">' +
							esc(t("Confirm")) + ' <strong>' + actName + '</strong> ' +
							esc(t("with your passkey.")) + '</p>',
						'<div class="passkey-confirm-actions">',
						'<button type="button" class="btn btn-primary passkey-confirm-passkey" ' +
							'autofocus>' + esc(t("Confirm with passkey")) + '</button>',
					];
					if (opts.canPassword) {
						lines.push(
							'<button type="button" class="btn btn-link passkey-confirm-usepw">' +
								esc(t("Use your password instead")) + '</button>'
						);
					}
					lines.push('</div>');
					lines.push('<div class="passkey-confirm-msg" aria-live="polite"></div>');
					lines.push('</div>');
					setContent(lines.join(""));
					seedA11y();

					var el = bodyEl();
					var pk = el && el.querySelector(".passkey-confirm-passkey");
					var pw = el && el.querySelector(".passkey-confirm-usepw");
					if (pk) {
						pk.addEventListener("click", function () { resolve("passkey"); });
						try { pk.focus(); } catch (e) { /* ignore */ }
					}
					if (pw) pw.addEventListener("click", function () { resolve("password"); });

					wireCancel(reject);
					show();
				});
			},

			// Prompt for the password (fallback path). Resolve with the string;
			// reject (user_cancelled) if the user dismisses the dialog.
			collectPassword: function () {
				return new Promise(function (resolve, reject) {
					// The engine can route STRAIGHT to the password leg (caps.passkey
					// false — a zero-credential user, or the sudo window expired) WITHOUT
					// ever calling chooseMethod, so the dialog may not exist yet. Create
					// it here too — mirrors the portal bundle's `if (!modal)` guard — or
					// setContent()/bodyEl() dereference a null dialog (TypeError crash).
					ensureDialog();
					var lead = t("Confirm your password to continue.");
					var html = [
						'<div class="passkey-confirm" role="group" aria-label="' +
							esc(t("Confirm with your password")) + '">',
						'<label class="passkey-confirm-pwlabel" for="passkey-confirm-pw">' +
							esc(lead) + '</label>',
						'<input type="password" id="passkey-confirm-pw" class="form-control ' +
							'passkey-confirm-pw" autocomplete="current-password" autofocus />',
						'<div class="passkey-confirm-actions">',
						'<button type="button" class="btn btn-primary passkey-confirm-pwgo">' +
							esc(t("Confirm")) + '</button>',
						'</div>',
						'<div class="passkey-confirm-msg" aria-live="assertive"></div>',
						'</div>',
					].join("");
					setContent(html);
					seedA11y();
					var el = bodyEl();
					var input = el && el.querySelector(".passkey-confirm-pw");
					var go = el && el.querySelector(".passkey-confirm-pwgo");
					function submit() {
						var v = input ? input.value : "";
						if (input) input.value = "";
						resolve(v);
					}
					if (go) go.addEventListener("click", submit);
					if (input) {
						input.addEventListener("keydown", function (ev) {
							if (ev.key === "Enter") { ev.preventDefault(); submit(); }
						});
						try { input.focus(); } catch (e) { /* ignore */ }
					}
					wireCancel(reject);
					show();
				});
			},

			passwordError: function (msg) {
				var el = bodyEl();
				var box = el && el.querySelector(".passkey-confirm-msg");
				if (box) box.textContent = msg;
				C.announce(document, msg);
			},

			announce: function (msg) {
				var el = bodyEl();
				var box = el && el.querySelector(".passkey-confirm-msg");
				if (box) box.textContent = msg;
				C.announce(document, msg);
			},

			busy: function (on) {
				var el = bodyEl();
				var pk = el && el.querySelector(".passkey-confirm-passkey");
				if (pk) pk.disabled = !!on;
			},

			done: function (ok) {
				void ok;
				try { if (dialog && dialog.hide) dialog.hide(); } catch (e) { /* ignore */ }
				if (restoreFocus) restoreFocus(); // focus returns to invoking control
			},

			close: function () { controller.done(false); },
		};

		// Esc / backdrop / dialog "hide" ⇒ user_cancelled, unless the engine has
		// already settled (done() sets _settled).
		function wireCancel(reject) {
			var fired = false;
			function cancel() {
				if (fired || controller._settled) return;
				fired = true;
				reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled.")));
			}
			if (dialog && dialog.$wrapper && dialog.$wrapper.on) {
				dialog.$wrapper.on("hide.bs.modal", cancel);
			} else if (dialog && dialog.onHide) {
				dialog.onHide = cancel;
			}
			// frappe.ui.Dialog primary Esc handling already dismisses; the hide
			// event above catches every dismissal route.
		}

		// mark settled so a programmatic hide (success) isn't read as a cancel
		var _origDone = controller.done;
		controller.done = function (ok) { controller._settled = true; _origDone(ok); };

		return controller;
	}

	// Minimal API-compatible dialog for the (shouldn't-happen) case where
	// frappe.ui.Dialog is absent — keeps the a11y contract (role/labelledby/Esc).
	function minimalDialog(title) {
		var wrap = document.createElement("div");
		wrap.className = "passkey-confirm-modal";
		wrap.setAttribute("role", "dialog");
		wrap.setAttribute("aria-modal", "true");
		wrap.setAttribute("aria-label", title);
		var body = document.createElement("div");
		body.className = "passkey-confirm-modal-body";
		wrap.appendChild(body);
		var onHideRef = { fn: null };
		function onKey(ev) { if (ev.key === "Escape") hide(); }
		function show() {
			(document.body || document.documentElement).appendChild(wrap);
			document.addEventListener("keydown", onKey, true);
		}
		function hide() {
			document.removeEventListener("keydown", onKey, true);
			if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
			if (api.onHide) api.onHide();
		}
		var api = {
			body: body,
			$body: null,
			show: show,
			hide: hide,
			onHide: null,
		};
		void onHideRef;
		return api;
	}

	// ------------------------------------------------------------------- engine
	var engine = C.createConfirmEngine({
		post: post,
		runGesture: runGesture,
		ui: makeDialogUI, // fresh controller per ceremony
		translate: t,
	});

	// -------------------------------------------------------------- public API
	function confirm(action, params) {
		if (!action) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.CONFIRMATION_FAILED, t("An action is required.")));
		return engine.confirm(action, params);
	}
	function call(method, args) {
		if (!method) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.CONFIRMATION_FAILED, t("A method is required.")));
		return engine.call(method, args);
	}

	publish({ confirm: confirm, call: call });

	function publish(api) {
		var f = (window.frappe = window.frappe || {});
		f.passkeys = f.passkeys || {};
		f.passkeys.confirm = api.confirm;
		f.passkeys.call = api.call;
		// forward-compat with the core destination namespace
		f.ui = f.ui || {};
		f.ui.passkey = f.ui.passkey || {};
		if (!f.ui.passkey.confirm) f.ui.passkey.confirm = api.confirm;
		if (!f.ui.passkey.call) f.ui.passkey.call = api.call;
	}

	function installStub() {
		var f = (window.frappe = window.frappe || {});
		f.passkeys = f.passkeys || {};
		function unavailable() {
			return Promise.reject({ code: "not_supported", message: "Passkey confirmation is unavailable." });
		}
		if (!f.passkeys.confirm) f.passkeys.confirm = unavailable;
		if (!f.passkeys.call) f.passkeys.call = unavailable;
	}

	// Node-only test seam (UMD-lite, mirrors passkey_common.js): expose the dialog
	// UI factory so `node --test` can exercise the straight-to-password route
	// without a bench/jsdom. No-op in the browser — `module` is undefined there.
	if (typeof module === "object" && module.exports) {
		module.exports = { makeDialogUI: makeDialogUI, minimalDialog: minimalDialog };
	}
})();
