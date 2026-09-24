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
			if (!dialog) {
				dialog = new window.frappe.ui.Dialog({
					title: t("Confirm it's you"),
					size: "small",
					fields: [
						{ fieldname: "summary", fieldtype: "HTML" },
						{ fieldname: "password", fieldtype: "Password", label: t("Password") },
						{
							fieldname: "alert",
							fieldtype: "HTML",
							options: '<div class="passkey-confirm-msg" role="alert" aria-live="assertive"></div>',
						},
					],
				});
			}
			return dialog;
		}

		function fieldWrap(name) {
			var field = dialog.fields_dict && dialog.fields_dict[name];
			return field && field.$wrapper;
		}

		function messageBox() {
			var wrap = fieldWrap("alert");
			var root = wrap && wrap.get && wrap.get(0);
			return root && root.querySelector ? root.querySelector(".passkey-confirm-msg") : null;
		}

		// Esc / backdrop / close all fire hide.bs.modal; after done() it is not a cancel.
		function armCancel(reject) {
			var fired = false;
			dialog.$wrapper.on("hide.bs.modal", function () {
				if (fired || settled) return;
				fired = true;
				reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled.")));
			});
		}

		function showPrompt(reject) {
			ensureDialog();
			armCancel(reject);
			dialog.show();
			C.ensureLiveRegion(document);
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
			var box = dialog && messageBox();
			if (box) box.textContent = msg;
			C.announce(document, msg);
		}

		function primaryBtn() {
			if (!dialog || !dialog.get_primary_btn) return null;
			return dialog.get_primary_btn();
		}

		function tagPrimary(addClass, removeClass) {
			var btn = primaryBtn();
			if (!btn) return;
			if (btn.addClass) btn.addClass(addClass);
			if (removeClass && btn.removeClass) btn.removeClass(removeClass);
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
						'</div>',
					].join("");
					showPrompt(reject);
					dialog.set_df_property("password", "hidden", 1);
					fieldWrap("summary").html(html);
					var polite = messageBox();
					if (polite) {
						polite.removeAttribute("role");
						polite.setAttribute("aria-live", "polite");
					}
					var picked = false;
					function pick(method) {
						if (picked) return;
						picked = true;
						resolve(method);
					}
					dialog.set_primary_action(t("Confirm with passkey"), function () { pick("passkey"); });
					tagPrimary("passkey-confirm-passkey", "passkey-confirm-pwgo");
					if (opts.canPassword) {
						dialog.set_secondary_action_label(t("Use your password instead"));
						dialog.set_secondary_action(function () { pick("password"); });
					}
					var pk = primaryBtn();
					if (pk && pk.focus) pk.focus();
				});
			},

			collectPassword: function (opts) {
				return new Promise(function (resolve, reject) {
					var action = actionName(opts || {});
					var html = [
						'<div class="passkey-confirm" role="group" aria-label="' + esc(t("Confirm with your password")) + '">',
						'<p class="passkey-confirm-action"><strong>' + esc(action.name) + '</strong></p>',
						summaryHtml(action.context.summary),
						'<p class="passkey-confirm-pwlabel">' + esc(t("Confirm your password to continue.")) + '</p>',
						'</div>',
					].join("");
					showPrompt(reject);
					dialog.set_df_property("password", "hidden", 0);
					fieldWrap("summary").html(html);
					var input = dialog.fields_dict.password.$input;
					if (input && input.addClass) {
						input.addClass("passkey-confirm-pw");
						if (input.attr) input.attr("autocomplete", "current-password");
					}
					var box = messageBox();
					if (box) {
						box.textContent = passwordMessage;
						box.setAttribute("role", "alert");
						box.setAttribute("aria-live", "assertive");
					}
					var submitted = false;
					function submit() {
						if (submitted) return;
						submitted = true;
						var value = dialog.get_value("password") || "";
						dialog.set_value("password", "");
						passwordMessage = "";
						resolve(value);
					}
					dialog.set_primary_action(t("Confirm"), submit);
					tagPrimary("passkey-confirm-pwgo", "passkey-confirm-passkey");
					var secondary = dialog.get_secondary_btn && dialog.get_secondary_btn();
					if (secondary && secondary.addClass) secondary.addClass("hide");
					if (input && input.on) {
						input.on("keydown", function (ev) {
							if (ev.key === "Enter") { ev.preventDefault(); submit(); }
						});
					}
					if (input && input.focus) input.focus();
				});
			},

			passwordError: function (msg) {
				passwordMessage = msg;
				showMessage(msg);
			},

			announce: showMessage,

			busy: function (on) {
				var pk = primaryBtn();
				if (!pk) return;
				if (pk.prop) pk.prop("disabled", !!on);
				else pk.disabled = !!on;
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
