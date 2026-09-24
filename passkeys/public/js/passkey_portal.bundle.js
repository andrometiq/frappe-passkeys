// Portal pages: the /passkeys page, and the enforcement gate and nudge banner on every
// authenticated portal page. Portal pages have no frappe.ui.Dialog or desk confirm bundle,
// so this builds its own modal and confirm UI. Loads after passkey_common,
// passkey_manage_common and passkey_headless.
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	var M = window.frappe && window.frappe.passkeys_manage_common;
	if (!C || !M) return;
	var t = C.t;
	var METHODS = M.MANAGE_METHODS;
	var post = C.post;
	var el = M.el;
	var events = M.createEnrollmentEvents(post);
	var recordNudge = events.recordNudge;

	var mountRoot = document.getElementById("passkey-portal-root");
	var statusRoot = document.getElementById("passkey-portal-status");
	var isPasskeyPage = !!mountRoot;

	function headless() { return window.frappe.passkeys.headless; }

	// -------------------------------------------------------- self-contained modal
	// role=dialog + aria-modal + focus trap + Esc + focus return. A `static` modal (a blocking
	// gate) ignores Esc, and there is no backdrop click, so it cannot be dismissed.
	function buildModal(cfg) {
		var restore = C.captureFocus(document);
		var overlay = el("div", "passkey-portal-overlay");
		var root = el("div", "passkey-dialog");
		root.setAttribute("role", "dialog");
		root.setAttribute("aria-modal", "true");
		var titleId = "passkey-portal-title-" + Date.now();
		root.setAttribute("aria-labelledby", titleId);
		var title = el("h4", "passkey-dialog-title", cfg.title);
		title.id = titleId;
		root.appendChild(title);
		var body = el("div", "passkey-dialog-body");
		root.appendChild(body);
		var actions = el("div", "passkey-dialog-actions");
		root.appendChild(actions);
		overlay.appendChild(root);

		function close() {
			if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
			document.removeEventListener("keydown", onKey, true);
			restore();
			if (cfg.onClose) cfg.onClose();
		}
		function onKey(e) {
			if (e.key === "Escape" && !cfg.static) {
				e.preventDefault();
				close();
				return;
			}
			if (e.key === "Tab") {
				var f = root.querySelectorAll("button, input, a[href], [tabindex]:not([tabindex='-1'])");
				if (!f.length) return;
				var first = f[0], last = f[f.length - 1];
				if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
				else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
			}
		}
		return {
			root: root, body: body, actions: actions, close: close,
			open: function () {
				(document.body || document.documentElement).appendChild(overlay);
				document.addEventListener("keydown", onKey, true);
				setTimeout(function () { var b = actions.querySelector("button"); if (b) b.focus(); }, 0);
			},
		};
	}

	// ----------------------------------------------- confirm engine (sudo dance)
	function appendConfirmationContext(body, opts, passwordOnly) {
		var context = C.confirmationActionContext(opts.action, opts.actionLabel, opts.parameterSummary);
		var label = context.labelFromServer ? context.label : t(context.label);
		var action = el("p", "passkey-confirm-action");
		action.appendChild(el("strong", "", label));
		body.appendChild(action);
		body.appendChild(el("p", "passkey-confirm-lead", opts.action === "passkeys.manage"
			? t("This sign-in hasn't been strongly verified recently. To manage your passkeys, confirm it's you below.")
			: passwordOnly
				? t("Confirm {0} to continue.", [label])
				: t("Confirm {0} with your passkey.", [label])));
		if (!context.summary.length) return;
		var summary = el("div", "passkey-confirm-summary");
		summary.setAttribute("aria-label", t("Action details"));
		context.summary.forEach(function (row) {
			var line = el("div", "passkey-confirm-summary-row");
			if (row.label) line.appendChild(el("span", "passkey-confirm-summary-label", row.label));
			line.appendChild(el("span", "passkey-confirm-summary-value", row.value));
			summary.appendChild(line);
		});
		body.appendChild(summary);
	}

	// The controller the engine drives (contract: docs/custom-ui.md).
	function makeConfirmUI() {
		var modal = null;
		var pendingReject = null;
		var passwordMessage = "";

		function freshModal() {
			var made = buildModal({ title: t("Confirm it's you"), onClose: function () {
				if (modal === made) modal = null;
				// A dismissal while a prompt is open cancels it.
				var reject = pendingReject;
				pendingReject = null;
				if (reject) reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled.")));
			} });
			modal = made;
		}
		function settle(resolve, value) {
			if (!pendingReject) return;
			pendingReject = null;
			resolve(value);
		}
		function cancelLink() {
			return M.button("link", t("Cancel"), function () { if (modal) modal.close(); });
		}
		return {
			chooseMethod: function (opts) {
				return new Promise(function (resolve, reject) {
					passwordMessage = "";
					freshModal();
					pendingReject = reject;
					appendConfirmationContext(modal.body, opts);
					modal.actions.appendChild(M.button("primary", t("Confirm with passkey"), function () { settle(resolve, "passkey"); }));
					if (opts.canPassword) {
						modal.actions.appendChild(M.button("link", t("Use your password instead"), function () { settle(resolve, "password"); }));
					}
					modal.actions.appendChild(cancelLink());
					modal.open();
				});
			},
			collectPassword: function (opts) {
				return new Promise(function (resolve, reject) {
					var mustOpen = !modal; // the engine can open straight on the password prompt
					if (mustOpen) freshModal();
					pendingReject = reject;
					modal.body.innerHTML = "";
					appendConfirmationContext(modal.body, opts || {}, true);
					var label = el("label", "", t("Confirm your password to continue."));
					label.setAttribute("for", "passkey-portal-pw");
					var input = el("input", "form-control");
					input.type = "password";
					input.id = "passkey-portal-pw";
					input.autocomplete = "current-password";
					modal.body.appendChild(label);
					modal.body.appendChild(input);
					var error = el("div", "passkey-confirm-msg", passwordMessage);
					error.setAttribute("role", "alert");
					error.setAttribute("aria-live", "assertive");
					modal.body.appendChild(error);
					modal.actions.innerHTML = "";
					function submit() {
						var value = input.value;
						input.value = "";
						passwordMessage = "";
						settle(resolve, value);
					}
					modal.actions.appendChild(M.button("primary", t("Confirm"), submit));
					modal.actions.appendChild(cancelLink());
					input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); submit(); } });
					if (mustOpen) modal.open();
					setTimeout(function () { input.focus(); }, 0);
				});
			},
			announce: announce,
			busy: function () {},
			passwordError: function (message) {
				passwordMessage = message;
				var box = modal && modal.body.querySelector(".passkey-confirm-msg");
				if (box) box.textContent = message;
				announce(message);
			},
			done: function () {
				pendingReject = null;
				if (!modal) return;
				var current = modal;
				modal = null;
				current.close();
			},
		};
	}
	var engine = C.createConfirmEngine({ post: post, runGesture: C.getAssertion, ui: makeConfirmUI, translate: t });
	// Any portal script (and the headless delete) can confirm through it.
	window.frappe.passkeys = window.frappe.passkeys || {};
	if (!window.frappe.passkeys.confirm) window.frappe.passkeys.confirm = engine.confirm;
	if (!window.frappe.passkeys.call) window.frappe.passkeys.call = engine.call;

	// ---------------------------------------------------------- card rendering
	function render() {
		mountRoot.innerHTML = "";
		C.ensureLiveRegion(document);
		mountRoot.appendChild(el("div", "passkey-cards-loading", t("Loading your passkeys…")));
		return Promise.all([post(METHODS.list, {}), M.loadAaguidMap()]).then(function (r) {
			mountRoot.innerHTML = "";
			var res = r[0];
			if (!res.ok) { mountRoot.appendChild(el("div", "passkey-cards-error", t("Couldn't load your passkeys."))); return; }
			var payload = C.unwrapMessage(res.body) || {};
			if (!(payload.credentials || []).length) { mountRoot.appendChild(M.emptyState(addPasskey)); return; }
			mountRoot.appendChild(M.cardList(payload.credentials, r[1], function (vm) {
				return { onRename: function () { renameCard(vm); }, onDelete: function () { deleteCard(vm); } };
			}));
			var addRow = el("div", "passkey-card-add-row");
			addRow.appendChild(M.button("primary", t(M.COPY.addButton), addPasskey));
			// For changes made on another device while the page is open.
			addRow.appendChild(M.button("link", t("Reload"), function () { render(); }));
			mountRoot.appendChild(addRow);
			mountRoot.appendChild(M.passkeyOnlyRow(payload, confirmPasskeyOnly));
		});
	}

	// Needs a single-use PASSKEY grant bound to {"enabled": <bool>}.
	function confirmPasskeyOnly(desired) {
		var modal = buildModal({ title: desired ? t("Turn on passwordless login?") : t("Turn off passwordless login?") });
		modal.body.appendChild(el("p", "", desired
			? t("Turning on passwordless login means you will not be able to log in with a password — only a passkey. Keep at least two passkeys so a lost device never locks you out.")
			: t("Password login will be allowed for your account again.")));
		modal.actions.appendChild(M.button("primary", desired ? t("Turn on passwordless login") : t("Turn off passwordless login"), function () {
			modal.close();
			setPortalStatus(t("Confirming it's you…"), "pending");
			engine.call(METHODS.setPasskeyOnly, { enabled: desired }).then(function () {
				setPortalStatus(desired ? t("Passwordless login is on.") : t("Passwordless login is off."), "success");
			}, function (err) {
				if (err && err.code === "user_cancelled") setPortalStatus("");
				else setPortalStatus((err && err.message) || t("Couldn't change passwordless login."), "error");
			}).then(render);
		}));
		modal.actions.appendChild(M.button("link", t("Cancel"), modal.close));
		modal.open();
	}

	function renameCard(vm) {
		var modal = buildModal({ title: t("Rename passkey") });
		var input = el("input", "form-control");
		input.type = "text";
		input.value = vm.label;
		input.setAttribute("aria-label", t(M.COPY.renamePrompt));
		modal.body.appendChild(el("label", "", t(M.COPY.renamePrompt)));
		modal.body.appendChild(input);
		modal.actions.appendChild(M.button("primary", t("Save"), function () {
			modal.close();
			setPortalStatus(t("Renaming passkey…"), "pending");
			headless().renameCredential(vm.name, input.value).then(function () {
				setPortalStatus(t("Passkey renamed."), "success");
				render();
			}, function (err) {
				setPortalStatus(err.message || t("Couldn't rename the passkey."), "error");
			});
		}));
		modal.actions.appendChild(M.button("link", t("Cancel"), modal.close));
		modal.open();
		setTimeout(function () { input.focus(); }, 0);
	}

	function deleteCard(vm) {
		var modal = buildModal({ title: t(M.COPY.deleteConfirmTitle) });
		modal.body.appendChild(el("p", "", M.format(t(M.COPY.deleteConfirmBody), [vm.label])));
		modal.actions.appendChild(M.button("primary", t(M.COPY.deleteConfirmCta), function () {
			modal.close();
			setPortalStatus(t("Confirming it's you…"), "pending");
			headless().removeCredential(vm.name).then(function () {
				setPortalStatus(t("Passkey removed."), "success");
				render();
			}, function (err) {
				if (err && err.code === "user_cancelled") { setPortalStatus(""); return; }
				setPortalStatus((err && err.message) || t("Couldn't remove the passkey."), "error");
			});
		}));
		modal.actions.appendChild(M.button("link", t("Cancel"), modal.close));
		modal.open();
	}

	// `onResult(ok)` lets the enforcement gate stay open until enrollment succeeds.
	function addPasskey(opts) {
		var onResult = (opts && opts.onResult) || function () {};
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
			setPortalStatus(t("This browser can't create passkeys."), "error");
			onResult(false);
			return;
		}
		setPortalStatus(t("Follow your device's prompt to add a passkey…"), "pending");
		headless().register({ flow: "explicit" }).then(function () {
			setPortalStatus(t("Passkey added."), "success");
			if (isPasskeyPage) render();
			onResult(true);
		}, function (err) {
			setPortalStatus(t(err && err.code === "already_registered" ? M.COPY.alreadyRegistered : M.COPY.addFailed), "error");
			onResult(false);
		});
	}

	// ------------------------------------------------ enforcement + nudge boot
	// Runs on every authenticated portal page, so a portal-only user cannot skip it by
	// avoiding /passkeys. Enforcement outranks the nudge.
	function maybeEnforceOrNudge() {
		var b = window.frappe.boot && window.frappe.boot.passkeys;
		if (!b || b.enabled === false) return;
		C.detectCapabilities({ window: window }).then(function (caps) {
			var enf = M.enforcementDecision(b, caps);
			if (enf.show) {
				if (enf.notifyAdmin) events.reportIncapableOnce();
				if (enf.variant === "enforce") showEnforceModal(b, enf);
				else renderNudgeBanner(); // an incapable device under Degrade
				return;
			}
			if (M.nudgeDecision(b, caps).showNudge) renderNudgeBanner();
		}).catch(function () {});
	}

	// The post-login enforcement interstitial. Blocking: a static modal whose only exits are
	// enrolling, the incapable escape and sign-out.
	function showEnforceModal(b, enf) {
		var modal = buildModal({
			title: t(M.COPY.enforceTitle),
			static: enf.blocking === true,
			// Esc on a non-blocking gate is "Remind me later"; `_settled` stops a double count.
			onClose: function () {
				if (!enf.blocking && !modal._settled) { modal._settled = true; events.recordEnforcementDefer(b, enf); }
			},
		});
		modal.body.appendChild(el("p", "", t(M.COPY.enforceBody)));
		modal.actions.appendChild(M.button("primary", t(M.COPY.nudgeCta), function () { enforceCreate(modal); }));
		if (!enf.blocking) {
			modal.actions.appendChild(M.button("link", M.format(t(M.COPY.enforceRemindLater), [enf.graceRemaining]), function () {
				events.recordEnforcementDefer(b, enf);
				modal._settled = true;
				modal.close();
			}));
		} else {
			// Only Block + Notify Admin notifies an administrator.
			var notifiesAdmin = (b.enforcement || {}).incapable_policy === "block_notify";
			modal.actions.appendChild(M.button("link", t(notifiesAdmin ? M.COPY.enforceContactAdmin : M.COPY.enforceCantSetUp), function () {
				onEnforceCantSetUp(b, modal);
			}));
			modal.actions.appendChild(M.button("link", t(M.COPY.enforceSignOut), signOut));
		}
		modal.open();
	}

	// A cancelled OS sheet must not dismiss a required gate.
	function enforceCreate(modal) {
		addPasskey({ onResult: function (ok) { if (ok) { modal._settled = true; modal.close(); } } });
	}

	// The blocking gate's escape: record it, then apply the incapable-device policy. Degrade
	// lets the user through (prompted again next page); Block + Notify Admin alerts the admin
	// and keeps the gate up with a notice.
	function onEnforceCantSetUp(b, modal) {
		events.reportIncapableOnce();
		if ((b.enforcement || {}).incapable_policy !== "block_notify") {
			modal._settled = true;
			modal.close();
			return;
		}
		modal.body.innerHTML = "";
		var notice = el("p", "", t(M.COPY.enforceBlockedNotice));
		notice.setAttribute("role", "alert");
		modal.body.appendChild(notice);
		modal.actions.innerHTML = "";
		modal.actions.appendChild(M.button("primary", t(M.COPY.enforceRetry), function () { enforceCreate(modal); }));
		modal.actions.appendChild(M.button("link", t(M.COPY.enforceSignOut), signOut));
	}

	// ------------------------------------------------------- portal nudge banner
	// A dismissible inline banner, never a modal.
	function renderNudgeBanner() {
		// /passkeys is the enrollment page itself: its empty state already offers the add.
		if (isPasskeyPage || document.getElementById("passkey-portal-nudge")) return;
		var host = document.querySelector(".page_content, main, body");
		if (!host) return;
		var bar = el("div", "passkey-nudge-banner");
		bar.id = "passkey-portal-nudge";
		bar.setAttribute("role", "region");
		bar.setAttribute("aria-label", t(M.COPY.nudgeTitle));
		bar.appendChild(el("strong", "passkey-nudge-title", t(M.COPY.nudgeTitle)));
		bar.appendChild(el("span", "passkey-nudge-copy", t(M.COPY.nudgeBody)));
		var acts = el("span", "passkey-nudge-acts");
		var optingOut = false, error = null;
		acts.appendChild(M.button("primary", t(M.COPY.nudgeCta), function () { location.href = "/passkeys"; }));
		acts.appendChild(M.button("link", t(M.COPY.nudgeLater), function () { recordNudge(M.NUDGE_EVENTS.DECLINED); bar.remove(); }));
		// Opt-out is permanent, so the banner stays until the server has saved it; a failure
		// is shown in place and the buttons stay usable for a retry.
		acts.appendChild(M.button("link", t(M.COPY.nudgeNever), function () {
			if (optingOut) return;
			optingOut = true;
			recordNudge(M.NUDGE_EVENTS.OPT_OUT).then(function (res) {
				optingOut = false;
				if (res && res.ok) { bar.remove(); return; }
				if (!error) {
					error = el("p", "passkey-nudge-error");
					error.setAttribute("role", "alert");
					bar.appendChild(error);
				}
				error.textContent = t(M.COPY.nudgeSaveFailed);
			});
		}));
		bar.appendChild(acts);
		host.insertBefore(bar, host.firstChild);
		recordNudge(M.NUDGE_EVENTS.SHOWN);
	}

	// --------------------------------------------------------------- utils
	function announce(msg) { C.announce(document, msg); }
	function signOut() { window.location.href = "/api/method/logout"; }

	// The status line above the /passkeys cards; elsewhere only the live region speaks.
	function setPortalStatus(msg, kind) {
		if (!statusRoot && mountRoot) {
			statusRoot = el("div", "passkey-portal-status");
			statusRoot.id = "passkey-portal-status";
			statusRoot.setAttribute("aria-live", "polite");
			mountRoot.parentNode.insertBefore(statusRoot, mountRoot);
		}
		if (!statusRoot) { if (msg) announce(msg); return; }
		statusRoot.hidden = !msg;
		statusRoot.className = "passkey-portal-status" + (msg ? " passkey-portal-status--" + (kind || "pending") : "");
		statusRoot.setAttribute("role", kind === "error" ? "alert" : "status");
		statusRoot.textContent = msg;
	}

	// --------------------------------------------------------------- boot
	// Web pages on v15/v16 carry no app strings: merge the catalog before the first paint.
	C.loadAppTranslations().then(function () {
		if (isPasskeyPage) render();
		maybeEnforceOrNudge();
	});

	// Node-only test seam; `module` is undefined in the browser.
	if (typeof module === "object" && module.exports) {
		module.exports = { showEnforceModal: showEnforceModal, buildModal: buildModal, makeConfirmUI: makeConfirmUI, setPortalStatus: setPortalStatus, renderNudgeBanner: renderNudgeBanner, maybeEnforceOrNudge: maybeEnforceOrNudge, recordNudge: recordNudge };
	}
})();
