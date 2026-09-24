// Desk credential management and enrollment prompts. Publishes `frappe.passkeys.manage`:
//   renderCards(container, opts)        the caller's own cards
//   renderReadOnlyInventory(el, user)   a System Manager's view of another user
//   renderEnforcementAdmin(el, user)    enforcement recovery for another user
//   openManagerDialog()                 the "My Passkeys" dialog
//   addPasskey(opts)                    registration (frappe.passkeys.headless.register)
//   refresh()                           re-render any live surface
// At Desk boot it runs the enforcement gate / nudge / conditional create / upsell from
// frappe.boot.passkeys. Loads after passkey_common, passkey_manage_common,
// passkey_headless and passkey_confirm.
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	var M = window.frappe && window.frappe.passkeys_manage_common;
	if (!C || !M) return;

	var t = C.t;
	var METHODS = M.MANAGE_METHODS;
	var post = C.post;
	var unwrap = C.unwrapMessage;
	var escapeHtml = C.escapeHtml;
	var el = M.el;
	var events = M.createEnrollmentEvents(post);
	var recordNudge = events.recordNudge;

	// A pending conditional create() holds the tab's WebAuthn request open, so every explicit
	// ceremony aborts it first ("A request is already pending" otherwise).
	var conditionalCreateAbort = null;
	function abortConditionalCreate() {
		if (conditionalCreateAbort) {
			conditionalCreateAbort.abort();
			conditionalCreateAbort = null;
		}
	}

	// ---------------------------------------------------------- mutations
	// Sudo-gated calls go through the confirm engine (the 401 contract, then one retry).
	function guardedCall(method, args) {
		abortConditionalCreate();
		return frappe.passkeys.call(method, args);
	}

	function addPasskey(opts) {
		abortConditionalCreate();
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
			var unsupported = new Error(t("This browser can't create passkeys."));
			unsupported.code = "not_supported";
			return Promise.reject(unsupported);
		}
		return frappe.passkeys.headless.register({ label: opts && opts.label });
	}

	function fireSignal(data) {
		M.signalCredentialState(window.PublicKeyCredential, data, boot().rp_id || location.hostname);
	}
	function refreshSignalsInSession() {
		post(METHODS.getSignalData, {}).then(function (res) {
			if (res.ok) fireSignal(unwrap(res.body));
		}).catch(function () {});
	}

	// ============================================================ card component
	// The caller's own credentials: rename (no sudo), delete (sudo-gated), empty state, add.
	function renderCards(container, opts) {
		opts = opts || {};
		if (!container) return;
		container.innerHTML = "";
		container.classList.add("passkey-cards-root");
		C.ensureLiveRegion(document);
		container.appendChild(el("div", "passkey-cards-loading", t("Loading your passkeys…")));

		return Promise.all([post(METHODS.list, {}), M.loadAaguidMap()]).then(function (r) {
			container.innerHTML = "";
			var res = r[0];
			if (!res.ok) {
				container.appendChild(el("div", "passkey-cards-error", t("Couldn't load your passkeys.")));
				return;
			}
			var payload = unwrap(res.body);
			var add = function () { triggerAdd(opts); };
			if (!payload.credentials.length) {
				container.appendChild(M.emptyState(add));
				return;
			}
			container.appendChild(M.cardList(payload.credentials, r[1], function (vm) {
				return {
					onRename: function () { renameCard(vm, opts); },
					onDelete: function () { deleteCard(vm, opts); },
				};
			}));
			var addRow = el("div", "passkey-card-add-row");
			addRow.appendChild(M.button("primary", t(M.COPY.addButton), add));
			container.appendChild(addRow);
			container.appendChild(M.passkeyOnlyRow(payload, function (desired) { confirmPasskeyOnly(desired, opts); }));
		});
	}

	// Display-only, no sudo.
	function renameCard(vm, opts) {
		var d = new frappe.ui.Dialog({
			title: t("Rename passkey"),
			fields: [{ fieldname: "label", fieldtype: "Data", label: t(M.COPY.renamePrompt), reqd: 1, default: vm.label }],
			primary_action_label: t("Save"),
			primary_action: function (values) {
				post(METHODS.rename, { name: vm.name, label: values.label }).then(function (res) {
					d.hide();
					if (res.ok) { announce(t("Passkey renamed.")); refresh(opts); }
					else frappe.msgprint(t("Couldn't rename the passkey."));
				});
			},
		});
		d.show();
	}

	// The server enforces the last-login-method guard; its refusal is shown verbatim.
	function deleteCard(vm, opts) {
		var d = new frappe.ui.Dialog({
			title: t(M.COPY.deleteConfirmTitle),
			indicator: "red",
			fields: [{ fieldtype: "HTML", options: "<p>" + escapeHtml(M.format(t(M.COPY.deleteConfirmBody), [vm.label])) + "</p>" }],
			primary_action_label: t(M.COPY.deleteConfirmCta),
			primary_action: function () {
				d.hide();
				announce(t("Confirming it's you…"));
				guardedCall(METHODS.del, { name: vm.name }).then(function () {
					refreshSignalsInSession();
					announce(t("Passkey removed."));
					refresh(opts);
				}).catch(function (err) {
					if (err && err.code === "user_cancelled") return;
					showFailure(t("Couldn't remove passkey"), err, t("Couldn't remove the passkey."));
				});
			},
		});
		d.show();
	}

	// Needs a single-use PASSKEY grant bound to {"enabled": <bool>}.
	function confirmPasskeyOnly(desired, opts) {
		var warn = desired
			? t("Turning on passwordless login means you will not be able to log in with a password — only a passkey. Keep at least two passkeys so a lost device never locks you out.")
			: t("Password login will be allowed for your account again.");
		var d = new frappe.ui.Dialog({
			title: desired ? t("Turn on passwordless login?") : t("Turn off passwordless login?"),
			indicator: desired ? "red" : "blue",
			fields: [{ fieldtype: "HTML", options: "<p>" + escapeHtml(warn) + "</p>" }],
			primary_action_label: desired ? t("Turn on passwordless login") : t("Turn off passwordless login"),
			primary_action: function () {
				d.hide();
				announce(t("Confirming it's you…"));
				guardedCall(METHODS.setPasskeyOnly, { enabled: desired }).then(function () {
					announce(desired ? t("Passwordless login is on.") : t("Passwordless login is off."));
				}).catch(function (err) {
					if (err && err.code === "user_cancelled") return;
					showFailure(t("Couldn't change passwordless login"), err, t("Couldn't change passwordless login."));
				}).then(function () { refresh(opts); });
			},
		});
		// Dismissing leaves the switch as it was: it snapped back before this dialog opened.
		d.show();
	}

	function triggerAdd(opts) {
		announce(t("Follow your device's prompt to add a passkey…"));
		addPasskey().then(function () {
			announce(t("Passkey added."));
			refresh(opts);
		}).catch(function (err) {
			if (err && err.code === "user_cancelled") return; // the user closed the OS sheet
			showFailure(t("Couldn't add passkey"), err, t(M.COPY.addFailed));
		});
	}

	function showFailure(title, err, fallback) {
		var message = (err && err.message) || fallback;
		frappe.msgprint({ title: title, message: escapeHtml(message), indicator: "orange" });
	}

	// A System Manager's read-only view of ANOTHER user, read from the DocType directly
	// (list_credentials returns only the session user's rows).
	function renderReadOnlyInventory(container, user) {
		if (!container) return;
		container.innerHTML = "";
		return Promise.all([
			frappe.db.get_list("WebAuthn Credential", {
				filters: { user: user },
				fields: ["name", "label", "enabled", "flagged", "flagged_reason", "backup_state", "aaguid", "last_used_at", "creation"],
				order_by: "creation asc",
				limit: 200,
			}),
			M.loadAaguidMap(),
		]).then(function (r) {
			var creds = r[0] || [];
			if (!creds.length) {
				container.appendChild(el("div", "passkey-cards-empty-admin", t("This user has no passkeys.")));
				return;
			}
			container.appendChild(M.cardList(creds, r[1], function () { return null; }));
			var link = el("a", "passkey-admin-link", t("Manage in the WebAuthn Credential list"));
			link.href = "/app/webauthn-credential?user=" + encodeURIComponent(user);
			container.appendChild(link);
		});
	}

	// ------------------------------------------------ admin enforcement recovery
	// Exemption and grace reset for ANOTHER user. Every endpoint re-checks
	// only_for("System Manager"); this is convenience, not the boundary.
	function adminCall(method, args) {
		return post(method, args).then(function (res) {
			if (res.ok) return unwrap(res.body);
			throw new Error("enforcement_admin_call_failed");
		});
	}

	function renderEnforcementAdmin(container, user, bootObj) {
		if (!container) return;
		container.innerHTML = "";
		if (!M.shouldShowEnforcementAdmin(bootObj || boot())) return;
		return adminCall(METHODS.getUserEnforcementAdmin, { user: user }).then(function (view) {
			paintEnforcementAdmin(container, user, view);
		}).catch(function () {
			container.innerHTML = ""; // no permission or no network: render nothing
		});
	}

	function paintEnforcementAdmin(container, user, view) {
		container.innerHTML = "";
		var vm = M.enforcementAdminViewModel(view);
		var wrap = el("div", "passkey-enforcement-admin");
		wrap.appendChild(el("div", "passkey-enforcement-admin-title text-muted", t(M.COPY.enforceAdminHeading)));

		var status = el("div", "passkey-enforcement-admin-status");
		status.appendChild(el("span", "indicator-pill " + vm.indicator.color, t(M.COPY[vm.indicator.textKey])));
		wrap.appendChild(status);

		var graceText = M.format(t(M.COPY.enforceAdminGrace), [vm.graceUsed, vm.graceTotal, vm.graceRemaining]);
		wrap.appendChild(el("div", "passkey-enforcement-admin-grace small text-muted", graceText));

		var actions = el("div", "passkey-enforcement-admin-actions");
		function setBusy(isBusy) {
			actions.querySelectorAll("button").forEach(function (b) { b.disabled = isBusy; });
		}
		function act(method, args, doneMessage) {
			setBusy(true);
			adminCall(method, args).then(function (next) {
				paintEnforcementAdmin(container, user, next);
				frappe.show_alert({ message: doneMessage(next), indicator: "green" });
			}).catch(function () {
				setBusy(false);
				frappe.msgprint({ title: t("Passkeys"), message: t(M.COPY.enforceAdminFailed), indicator: "orange" });
			});
		}
		var exemptBtn = el("button", "btn btn-xs " + (vm.exemptButtonPrimary ? "btn-primary" : "btn-default"), t(M.COPY[vm.exemptButtonKey]));
		exemptBtn.type = "button";
		exemptBtn.addEventListener("click", function () {
			act(METHODS.setUserExemption, { user: user, exempt: vm.nextExemptValue }, function (next) {
				return M.format(t(next.exempt ? M.COPY.enforceAdminExemptDone : M.COPY.enforceAdminUnexemptDone), [user]);
			});
		});
		actions.appendChild(exemptBtn);

		var resetBtn = el("button", "btn btn-xs btn-default", t(M.COPY.enforceAdminReset));
		resetBtn.type = "button";
		resetBtn.disabled = vm.resetDisabled;
		resetBtn.addEventListener("click", function () {
			act(METHODS.resetEnforcementGrace, { user: user }, function (next) {
				return M.format(t(M.COPY.enforceAdminResetDone), [next.grace_total]);
			});
		});
		actions.appendChild(resetBtn);

		wrap.appendChild(actions);
		container.appendChild(wrap);
	}

	// ---------------------------------------------------------- manager dialog
	var managerDialog = null;
	function openManagerDialog() {
		if (!managerDialog) {
			var d = new frappe.ui.Dialog({ title: t("My Passkeys"), size: "large" });
			var root = el("div", "passkey-manager");
			d.$body.get(0).appendChild(root);
			d._passkeyRoot = root;
			// Picks up changes made on another device while the dialog is open.
			d.add_custom_action(t("Reload"), function () { refresh({ root: root }); });
			managerDialog = d;
		}
		managerDialog.show();
		// Render on every open: $wrapper.is(":visible") is still false mid fade-in.
		refresh({ root: managerDialog._passkeyRoot });
		return managerDialog;
	}

	function refresh(opts) {
		opts = opts || {};
		if (opts.root) return renderCards(opts.root, opts);
		if (managerDialog && managerDialog.$wrapper.is(":visible")) {
			renderCards(managerDialog._passkeyRoot, { root: managerDialog._passkeyRoot });
		}
		// user_passkeys.js re-renders the User-form section on this event.
		document.dispatchEvent(new CustomEvent("passkey:changed"));
	}

	// ============================================================ nudges
	function boot() { return frappe.boot.passkeys || {}; }

	function maybeNudge() {
		var b = frappe.boot && frappe.boot.passkeys;
		if (!b) return;
		return Promise.all([C.detectCapabilities({ window: window }), probeConditionalCreate()]).then(function (r) {
			var caps = r[0];
			var clientCaps = {
				supported: caps.supported,
				uvpaa: caps.uvpaa,
				hybrid: caps.hybrid,
				conditionalCreate: r[1] === true,
			};
			// The enforcement gate outranks the nudge and the upsell.
			var enf = M.enforcementDecision(b, clientCaps);
			if (enf.show) {
				if (enf.notifyAdmin) events.reportIncapableOnce();
				if (enf.variant === "enforce") return showEnforceDialog(b, enf);
				return showNudgeDialog(b, false); // an incapable device under Degrade
			}
			// The post-hybrid upsell comes first: the login just happened over hybrid.
			var upsell = M.upsellDecision(b, clientCaps, storageGet);
			clearUpsellFlag();
			if (upsell.showUpsell) return showNudgeDialog(b, true);
			var d = M.nudgeDecision(b, clientCaps);
			// Silent conditional create first; Firefox has none, so the visible nudge is its path.
			if (d.allowConditionalCreate) return conditionalCreate(function () { if (d.showNudge) showNudgeDialog(b, false); });
			if (d.showNudge) showNudgeDialog(b, false);
		}).then(markNudgeEvaluated, markNudgeEvaluated);
	}

	// Set once the boot decision has run, whatever it decided, so specs can assert absence.
	function markNudgeEvaluated() {
		document.documentElement.setAttribute("data-passkeys-nudge-evaluated", "true");
	}

	// getClientCapabilities().conditionalCreate is the only reliable signal; unknown ⇒ false.
	function probeConditionalCreate() {
		var PKC = window.PublicKeyCredential;
		if (!PKC || typeof PKC.getClientCapabilities !== "function") return Promise.resolve(false);
		return Promise.resolve().then(function () { return PKC.getClientCapabilities(); })
			.then(function (caps) { return !!(caps && caps.conditionalCreate); })
			.catch(function () { return false; });
	}

	function showNudgeDialog(b, isUpsell) {
		var d = new frappe.ui.Dialog({ title: t(isUpsell ? M.COPY.upsellTitle : M.COPY.nudgeTitle), size: "small" });
		var body = d.$body.get(0);
		var act = function (event) { if (d._acted) return; d._acted = true; recordNudge(event); d.hide(); };
		var optingOut = false;
		var error = null;
		// Opt-out is permanent, so the dialog stays until the server has saved it; a failure
		// is shown in place and the buttons stay usable for a retry.
		var optOut = function () {
			if (d._acted || optingOut) return;
			optingOut = true;
			recordNudge(M.NUDGE_EVENTS.OPT_OUT).then(function (res) {
				optingOut = false;
				if (res && res.ok) { d._acted = true; d.hide(); return; }
				if (!error) { error = el("p", "passkey-nudge-error"); error.setAttribute("role", "alert"); body.appendChild(error); }
				error.textContent = t(M.COPY.nudgeSaveFailed);
			});
		};
		body.appendChild(el("p", "passkey-nudge-body", t(isUpsell ? M.COPY.upsellBody : M.COPY.nudgeBody)));
		// The CTA runs under the fresh-login sudo window: no re-prompt.
		d.set_primary_action(t(M.COPY.nudgeCta), function () { d._acted = true; d.hide(); triggerAdd({}); });
		d.set_secondary_action_label(t(M.COPY.nudgeLater));
		d.set_secondary_action(function () { act(M.NUDGE_EVENTS.DECLINED); });
		d.add_custom_action(t(M.COPY.nudgeNever), optOut);
		// Esc / backdrop dismissal means "Not now"; hide.bs.modal catches every route.
		d.$wrapper.on("hide.bs.modal", function () { if (!d._acted) { d._acted = true; recordNudge(M.NUDGE_EVENTS.DECLINED); } });
		d.show();
		recordNudge(M.NUDGE_EVENTS.SHOWN);
	}

	function conditionalCreate(onNotUpgraded) {
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") { onNotUpgraded(); return; }
		var upgraded = false;
		return post(METHODS.beginRegistration, { flow: "conditional_create" }).then(function (res) {
			if (!res.ok) return;
			var begin = unwrap(res.body) || {};
			// An explicit ceremony may already be running; this one yields to it.
			abortConditionalCreate();
			var controller = new AbortController();
			conditionalCreateAbort = controller;
			return C.createCredential(begin.options, { mediation: "conditional", signal: controller.signal }).then(function (credential) {
				conditionalCreateAbort = null;
				return post(METHODS.verifyRegistration, { state_id: begin.state_id, credential: JSON.stringify(credential) }).then(function (v) {
					if (!v.ok) return;
					upgraded = true;
					fireSignal(unwrap(v.body));
				});
			});
		}).then(function () {
			if (!upgraded) onNotUpgraded();
		}, function (err) {
			conditionalCreateAbort = null;
			if (!upgraded && (!err || err.name !== "AbortError")) onNotUpgraded();
		});
	}

	// ------------------------------------------------------ enforcement gate
	// The post-login interstitial. A blocking gate's only exits are enrolling, the incapable
	// escape and sign-out; "Remind me later" shows the real remaining grace count.
	function showEnforceDialog(b, enf) {
		// `static` stops Esc, backdrop clicks and the close-X; `keep_open` survives the desk
		// container's page switch.
		var d = new frappe.ui.Dialog({
			title: t(M.COPY.enforceTitle), size: "small",
			static: !!enf.blocking, keep_open: !!enf.blocking,
		});
		var body = d.$body.get(0);
		body.appendChild(el("p", "passkey-nudge-body", t(M.COPY.enforceBody)));
		// Runs under the fresh-login sudo window; the gate stays open until enrollment succeeds.
		d.set_primary_action(t(M.COPY.nudgeCta), function () { enforceCreate(d); });
		var signOutAction = null;
		if (!enf.blocking) {
			d.set_secondary_action_label(M.format(t(M.COPY.enforceRemindLater), [enf.graceRemaining]));
			d.set_secondary_action(function () {
				d._acted = true; events.recordEnforcementDefer(b, enf); d.hide();
			});
			// Any other dismissal is also "Remind me later"; `_acted` stops a double count.
			d.$wrapper.on("hide.bs.modal", function () {
				if (!d._acted) { d._acted = true; events.recordEnforcementDefer(b, enf); }
			});
		} else {
			// Only Block + Notify Admin notifies an administrator.
			var notifiesAdmin = (b.enforcement || {}).incapable_policy === "block_notify";
			d.set_secondary_action_label(t(notifiesAdmin ? M.COPY.enforceContactAdmin : M.COPY.enforceCantSetUp));
			d.set_secondary_action(function () { onEnforceCantSetUp(b, d, body); });
			signOutAction = d.add_custom_action(t(M.COPY.enforceSignOut), function () { frappe.app.logout(); });
			// The router hides any open dialog on a route change, ignoring static/keep_open,
			// so a blocking gate re-opens itself until the user takes one of its exits.
			d.$wrapper.on("hidden.bs.modal", function () { if (!d._acted) d.show(); });
		}
		d._signOutAction = signOutAction;
		// Bootstrap 4 drops hide() during a show transition (e.g. the re-open above), so an
		// exit taken mid-animation closes once the modal has settled.
		d.$wrapper.on("shown.bs.modal", function () { if (d._acted) d.hide(); });
		d.show();
	}

	function enforceCreate(d) {
		announce(t("Follow your device's prompt to add a passkey…"));
		addPasskey().then(function () {
			announce(t("Passkey added."));
			d._acted = true; d.hide(); refresh({});
		}).catch(function (err) {
			// A cancelled OS sheet keeps the (possibly blocking) gate open, without scolding.
			if (err && err.code === "user_cancelled") return;
			showFailure(t("Couldn't add passkey"), err, t(M.COPY.addFailed));
		});
	}

	// The blocking gate's escape: record it, then apply the incapable-device policy. Degrade
	// lets the user through (prompted again next session); Block + Notify Admin alerts the
	// admin and keeps the gate up with a notice.
	function onEnforceCantSetUp(b, d, body) {
		events.reportIncapableOnce();
		if ((b.enforcement || {}).incapable_policy !== "block_notify") {
			d._acted = true;
			d.hide();
			return;
		}
		body.innerHTML = "";
		var notice = el("p", "passkey-nudge-body", t(M.COPY.enforceBlockedNotice));
		notice.setAttribute("role", "alert");
		body.appendChild(notice);
		if (d._signOutAction && d._signOutAction.remove) d._signOutAction.remove();
		d._signOutAction = null;
		d.set_primary_action(t(M.COPY.enforceRetry), function () { enforceCreate(d); });
		d.set_secondary_action_label(t(M.COPY.enforceSignOut));
		d.set_secondary_action(function () { frappe.app.logout(); });
	}

	// ------------------------------------------------------------ small utils
	function storageGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
	function clearUpsellFlag() { try { localStorage.removeItem(M.UPSELL_FLAG_KEY); } catch (e) { /* storage unavailable */ } }
	function announce(msg) { C.announce(document, msg); }

	// ------------------------------------------------------------------ publish
	var manage = {
		renderCards: renderCards,
		renderReadOnlyInventory: renderReadOnlyInventory,
		renderEnforcementAdmin: renderEnforcementAdmin,
		openManagerDialog: openManagerDialog,
		addPasskey: addPasskey,
		refresh: refresh,
		triggerAdd: triggerAdd,
		recordNudge: recordNudge,
		METHODS: METHODS,
	};
	frappe.passkeys = frappe.passkeys || {};
	frappe.passkeys.manage = manage;
	frappe.ui.passkey = frappe.ui.passkey || {};
	if (!frappe.ui.passkey.manage) frappe.ui.passkey.manage = manage;

	// ------------------------------------------------------------- desk boot
	// A route change (container.js change_to) hides `cur_dialog`, and after_ajax can fire
	// before the landing page renders; a nudge opened then would be torn down and record a
	// decline the user never made. So wait for the first page render.
	function onReady() {
		var b = frappe.boot.passkeys;
		// Both modes off, or a dormant app (no boot payload): the UI removes itself.
		if (!b || b.enabled === false) return;
		if (frappe.container && frappe.container.page) maybeNudge();
		else $(document).one("page-change", maybeNudge);
		refreshSignalsInSession();
	}

	// Node-only test seam; `module` is undefined in the browser.
	if (typeof module === "object" && module.exports) {
		module.exports = { showEnforceDialog: showEnforceDialog, showNudgeDialog: showNudgeDialog, maybeNudge: maybeNudge, recordNudge: recordNudge };
	} else {
		frappe.after_ajax(onReady);
	}
})();
