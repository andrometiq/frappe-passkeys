// Desk client for action confirmation: publishes frappe.passkeys.confirm / .call (aliased
// at frappe.ui.passkey.*) over the engine in passkey_common, with a frappe.ui.Dialog UI.
// Loads after passkey_common.
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	if (!C) return;
	var t = C.t;
	var esc = C.escapeHtml;

	// The controller the engine drives; a fresh one per ceremony.
	function makeDialogUI() {
		var dialog = null;
		var restoreFocus = C.captureFocus(document);
		var focusRestored = false;
		var settled = false;
		// A wrong-password message survives the prompt's re-render until the next submit.
		var passwordMessage = "";
		function restoreCapturedFocus() {
			if (focusRestored) return;
			focusRestored = true;
			restoreFocus();
		}

		// The engine can go straight to the password leg, so either prompt may open it.
		function ensureDialog() {
			if (!dialog) dialog = new window.frappe.ui.Dialog({ title: t("Confirm it's you"), size: "small" });
			return dialog;
		}

		function bodyEl() { return dialog.$body.get(0); }

		function render(html, reject) {
			ensureDialog();
			dialog.$body.html(html);
			// Esc / backdrop / close all fire hide.bs.modal; after done() it is not a cancel.
			var fired = false;
			dialog.$wrapper.on("hide.bs.modal", function () {
				if (fired || settled) return;
				fired = true;
				reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled.")));
			});
			dialog.show();
			C.ensureLiveRegion(document);
			return bodyEl();
		}

		function actionName(opts) {
			var context = C.confirmationActionContext(opts.action, opts.actionLabel, opts.parameterSummary);
			return { context: context, name: context.labelFromServer ? context.label : t(context.label) };
		}

		function summaryHtml(rows) {
			if (!rows.length) return "";
			var out = ['<div class="passkey-confirm-summary" aria-label="' + esc(t("Action details")) + '">'];
			rows.forEach(function (row) {
				if (row.label) {
					out.push('<div class="passkey-confirm-summary-row"><span class="passkey-confirm-summary-label">' +
						esc(row.label) + '</span><span class="passkey-confirm-summary-value">' +
						esc(row.value) + '</span></div>');
				} else {
					out.push('<div class="passkey-confirm-summary-value">' + esc(row.value) + '</div>');
				}
			});
			out.push("</div>");
			return out.join("");
		}

		function showMessage(msg) {
			var box = dialog && bodyEl().querySelector(".passkey-confirm-msg");
			if (box) box.textContent = msg;
			C.announce(document, msg);
		}

		var controller = {
			chooseMethod: function (opts) {
				return new Promise(function (resolve, reject) {
					var action = actionName(opts);
					// The built-in management action explains why; others name the action.
					var lead = opts.action === "passkeys.manage"
						? t("This sign-in hasn't been strongly verified recently. To manage your passkeys, confirm it's you below.")
						: t("Confirm {0} with your passkey.", [action.name]);
					var html = [
						'<div class="passkey-confirm" role="group" aria-label="' + esc(t("Confirm this action with a passkey")) + '">',
						'<p class="passkey-confirm-action"><strong>' + esc(action.name) + '</strong></p>',
						'<p class="passkey-confirm-lead">' + esc(lead) + '</p>',
						summaryHtml(action.context.summary),
						'<div class="passkey-confirm-actions">',
						'<button type="button" class="btn btn-primary passkey-confirm-passkey" autofocus>' +
							esc(t("Confirm with passkey")) + '</button>',
						opts.canPassword
							? '<button type="button" class="btn btn-default btn-sm passkey-confirm-usepw">' +
								esc(t("Use your password instead")) + '</button>'
							: "",
						'</div>',
						'<div class="passkey-confirm-msg" aria-live="polite"></div>',
						'</div>',
					].join("");
					var el = render(html, reject);
					var pk = el.querySelector(".passkey-confirm-passkey");
					var pw = el.querySelector(".passkey-confirm-usepw");
					if (pk) {
						pk.addEventListener("click", function () { resolve("passkey"); });
						pk.focus();
					}
					if (pw) pw.addEventListener("click", function () { resolve("password"); });
				});
			},

			collectPassword: function (opts) {
				return new Promise(function (resolve, reject) {
					var action = actionName(opts || {});
					var html = [
						'<div class="passkey-confirm" role="group" aria-label="' + esc(t("Confirm with your password")) + '">',
						'<p class="passkey-confirm-action"><strong>' + esc(action.name) + '</strong></p>',
						summaryHtml(action.context.summary),
						'<label class="passkey-confirm-pwlabel" for="passkey-confirm-pw">' +
							esc(t("Confirm your password to continue.")) + '</label>',
						'<input type="password" id="passkey-confirm-pw" class="form-control ' +
							'passkey-confirm-pw" autocomplete="current-password" autofocus />',
						'<div class="passkey-confirm-actions">',
						'<button type="button" class="btn btn-primary passkey-confirm-pwgo">' + esc(t("Confirm")) + '</button>',
						'</div>',
						'<div class="passkey-confirm-msg" role="alert" aria-live="assertive">' + esc(passwordMessage) + '</div>',
						'</div>',
					].join("");
					var el = render(html, reject);
					var input = el.querySelector(".passkey-confirm-pw");
					var go = el.querySelector(".passkey-confirm-pwgo");
					function submit() {
						var value = input ? input.value : "";
						if (input) input.value = "";
						passwordMessage = "";
						resolve(value);
					}
					if (go) go.addEventListener("click", submit);
					if (input) {
						input.addEventListener("keydown", function (ev) {
							if (ev.key === "Enter") { ev.preventDefault(); submit(); }
						});
						input.focus();
					}
				});
			},

			passwordError: function (msg) {
				passwordMessage = msg;
				showMessage(msg);
			},

			announce: showMessage,

			busy: function (on) {
				var pk = dialog && bodyEl().querySelector(".passkey-confirm-passkey");
				if (pk) pk.disabled = !!on;
			},

			done: function () {
				settled = true;
				if (!dialog) { restoreCapturedFocus(); return; }
				// Bootstrap moves focus while hiding, so restore only once it has finished.
				dialog.$wrapper.one("hidden.bs.modal", restoreCapturedFocus);
				dialog.hide();
				// Bootstrap 4 ignores hide() during the show transition; hide again once shown.
				dialog.$wrapper.one("shown.bs.modal", function () { dialog.$wrapper.modal("hide"); });
			},
		};
		return controller;
	}

	var engine = C.createConfirmEngine({
		post: C.post,
		runGesture: C.getAssertion,
		ui: makeDialogUI,
		translate: t,
	});

	function confirm(action, params) {
		if (!action) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.CONFIRMATION_FAILED, t("An action is required.")));
		return engine.confirm(action, params);
	}
	function call(method, args) {
		if (!method) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.CONFIRMATION_FAILED, t("A method is required.")));
		return engine.call(method, args);
	}

	var f = window.frappe;
	f.passkeys = f.passkeys || {};
	f.passkeys.confirm = confirm;
	f.passkeys.call = call;
	f.ui = f.ui || {};
	f.ui.passkey = f.ui.passkey || {};
	if (!f.ui.passkey.confirm) f.ui.passkey.confirm = confirm;
	if (!f.ui.passkey.call) f.ui.passkey.call = call;

	// Node-only test seam; `module` is undefined in the browser.
	if (typeof module === "object" && module.exports) {
		module.exports = { makeDialogUI: makeDialogUI };
	}
})();
