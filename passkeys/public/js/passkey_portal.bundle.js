// passkey_portal.bundle.js — the portal /passkeys page, the enforcement gate and the
// nudge banner on authenticated portal pages. Loads AFTER passkey_common and
// passkey_manage_common. Portal pages have no frappe.ui.Dialog or desk confirm bundle,
// so this builds its own modal and confirm engine (C.createConfirmEngine).
//
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	var M = window.frappe && window.frappe.passkeys_manage_common;
	if (!C || !M) return;
	var t = C.t;
	var METHODS = M.MANAGE_METHODS;

	var mountRoot = document.getElementById("passkey-portal-root");
	var statusRoot = document.getElementById("passkey-portal-status");
	var isPasskeyPage = !!mountRoot;

	var post = C.post;
	var unwrap = C.unwrapMessage;

	// -------------------------------------------------------- self-contained modal
	// role=dialog + aria-modal + focus trap + Esc + focus return.
	function buildModal(cfg) {
		var restore = C.captureFocus(document);
		var overlay = el("div", "passkey-portal-overlay");
		var root = el("div", "passkey-dialog");
		root.setAttribute("role", "dialog");
		root.setAttribute("aria-modal", "true");
		var titleId = "passkey-portal-title-" + Date.now();
		root.setAttribute("aria-labelledby", titleId);
		var h = el("h4", "passkey-dialog-title", cfg.title); h.id = titleId;
		root.appendChild(h);
		var bodyEl = el("div", "passkey-dialog-body");
		root.appendChild(bodyEl);
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
			// A static modal (a blocking enforcement gate) suppresses Esc dismissal —
			// the overlay never wires a backdrop-click either, so it cannot be dismissed.
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
			root: root, body: bodyEl, actions: actions, close: close,
			open: function () {
				(document.body || document.documentElement).appendChild(overlay);
				document.addEventListener("keydown", onKey, true);
				setTimeout(function () { var b = actions.querySelector("button"); if (b) b.focus(); }, 0);
			},
		};
	}

	// ----------------------------------------------- confirm engine (sudo dance)
	// The portal's frappe.passkeys.confirm/call: the pure engine + this modal adapter.
	function appendConfirmationContext(body, opts, passwordOnly) {
		var context = C.confirmationActionContext(opts.action, opts.actionLabel, opts.parameterSummary);
		var label = context.labelFromServer ? context.label : t(context.label);
		var action = el("p", "passkey-confirm-action");
		var strong = el("strong", "", label);
		action.appendChild(strong);
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

	function makeConfirmUI() {
		var modal = null;
		var pendingReject = null;
		var pending = false;
		var passwordMessage = "";

		function cancelled() {
			if (!pending) return;
			pending = false;
			var reject = pendingReject;
			pendingReject = null;
			if (reject) reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled.")));
		}
		function freshModal() {
			var made = buildModal({ title: t("Confirm it's you"), onClose: function () {
				if (modal === made) modal = null;
				cancelled();
			} });
			modal = made;
			return made;
		}
		function beginPending(reject) {
			pending = true;
			pendingReject = reject;
		}
		function settle(resolve, value) {
			if (!pending) return;
			pending = false;
			pendingReject = null;
			resolve(value);
		}
		function closeSettled() {
			pending = false;
			pendingReject = null;
			if (!modal) return;
			var current = modal;
			modal = null;
			current.close();
		}
		return {
			chooseMethod: function (opts) {
				return new Promise(function (resolve, reject) {
					passwordMessage = "";
					freshModal();
					beginPending(reject);
					appendConfirmationContext(modal.body, opts);
					var pk = primary(t("Confirm with passkey"), function () { settle(resolve, "passkey"); });
					modal.actions.appendChild(pk);
					if (opts.canPassword) modal.actions.appendChild(link(t("Use your password instead"), function () { settle(resolve, "password"); }));
					modal.actions.appendChild(link(t("Cancel"), function () { if (modal) modal.close(); }));
					modal.open();
				});
			},
			collectPassword: function (opts) {
				return new Promise(function (resolve, reject) {
					opts = opts || {};
					var mustOpen = !modal;
					if (!modal) freshModal();
					beginPending(reject);
					modal.body.innerHTML = "";
					appendConfirmationContext(modal.body, opts, true);
					var lbl = el("label", "", t("Confirm your password to continue.")); lbl.setAttribute("for", "passkey-portal-pw");
					var input = document.createElement("input");
					input.type = "password";
					input.id = "passkey-portal-pw";
					input.className = "form-control";
					input.autocomplete = "current-password";
					modal.body.appendChild(lbl); modal.body.appendChild(input);
					var error = el("div", "passkey-confirm-msg", passwordMessage);
					error.setAttribute("role", "alert"); error.setAttribute("aria-live", "assertive");
					modal.body.appendChild(error);
					modal.actions.innerHTML = "";
					function submit() {
						var v = input.value;
						input.value = "";
						passwordMessage = "";
						settle(resolve, v);
					}
					modal.actions.appendChild(primary(t("Confirm"), submit));
					modal.actions.appendChild(link(t("Cancel"), function () { if (modal) modal.close(); }));
					input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); submit(); } });
					if (mustOpen) modal.open();
					setTimeout(function () { input.focus(); }, 0);
				});
			},
			announce: function (m) { announce(m); },
			busy: function () {},
			passwordError: function (m) {
				passwordMessage = m;
				if (modal) {
					var box = modal.body.querySelector(".passkey-confirm-msg");
					if (box) box.textContent = m;
				}
				announce(m);
			},
			done: closeSettled,
			close: closeSettled,
		};
	}
	var engine = C.createConfirmEngine({ post: post, runGesture: C.getAssertion, ui: makeConfirmUI, translate: t });
	// publish so any portal script (and our own delete path) can re-auth
	window.frappe = window.frappe || {};
	window.frappe.passkeys = window.frappe.passkeys || {};
	if (!window.frappe.passkeys.confirm) window.frappe.passkeys.confirm = engine.confirm;
	if (!window.frappe.passkeys.call) window.frappe.passkeys.call = engine.call;

	// ------------------------------------------------------------------ AAGUID
	var _map = null;
	function loadMap() {
		if (_map) return Promise.resolve(_map);
		return fetch("/assets/passkeys/aaguid-map.json", { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; })
			.then(function (m) { _map = m || {}; return _map; });
	}

	// ---------------------------------------------------------- card rendering
	function render() {
		if (!mountRoot) return;
		mountRoot.innerHTML = "";
		C.ensureLiveRegion(document);
		mountRoot.appendChild(el("div", "passkey-cards-loading", t("Loading your passkeys…")));
		return Promise.all([post(METHODS.list, {}), loadMap()]).then(function (r) {
			mountRoot.innerHTML = "";
			var res = r[0], map = r[1];
			if (!res || !res.ok) { mountRoot.appendChild(el("div", "passkey-cards-error", t("Couldn't load your passkeys."))); return; }
			var payload = unwrap(res.body) || {};
			var creds = payload.credentials || [];
			if (!creds.length) { mountRoot.appendChild(emptyState()); return; }
			var list = el("ul", "passkey-card-list"); list.setAttribute("role", "list");
			creds.forEach(function (cred) { list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map, translate: t }))); });
			mountRoot.appendChild(list);
			mountRoot.appendChild(addRow());
			mountRoot.appendChild(passkeyOnlyRow(creds, payload)); // passwordless-login switch
		});
	}

	// Passwordless-login switch. The value comes from the list payload, else boot, else off.
	function isPasskeyOnly(payload) {
		if (payload && payload.passkey_only_login !== undefined) return !!payload.passkey_only_login;
		var b = (window.frappe && frappe.boot && frappe.boot.passkeys) || null;
		return !!(b && b.passkey_only_login);
	}
	function passkeyOnlyRow(creds, payload) {
		var enabledCount = 0;
		creds.forEach(function (c) { if (M.credentialViewModel(c, { translate: t }).enabled) enabledCount += 1; });
		var current = isPasskeyOnly(payload);
		var availability = M.passkeyOnlyAvailability(enabledCount, current);
		var row = el("div", "passkey-only-row");
		var main = el("div", "passkey-only-main");
		main.appendChild(el("div", "passkey-only-label", t(M.COPY.passkeyOnlyLabel)));
		main.appendChild(el("div", "passkey-only-help", t(M.COPY[availability.helpKey])));
		row.appendChild(main);
		var toggle = document.createElement("input");
		toggle.type = "checkbox";
		toggle.className = "passkey-only-toggle";
		toggle.checked = current;
		toggle.setAttribute("role", "switch"); toggle.setAttribute("aria-checked", current ? "true" : "false");
		toggle.setAttribute("aria-label", t(M.COPY.passkeyOnlyLabel));
		if (availability.disabled) { toggle.disabled = true; toggle.setAttribute("title", t(M.COPY.passkeyOnlyNeedsTwo)); }
		toggle.addEventListener("change", function () {
			var desired = toggle.checked;
			toggle.checked = current; // don't flip until the sudo-gated call confirms
			confirmPasskeyOnly(desired, current);
		});
		row.appendChild(toggle);
		return row;
	}
	// Needs a single-use PASSKEY grant; the server binds it to the {"enabled": <bool>} payload.
	function confirmPasskeyOnly(desired, current) {
		if (desired === current) return;
		var modal = buildModal({ title: desired ? t("Turn on passwordless login?") : t("Turn off passwordless login?") });
		modal.body.appendChild(el("p", "", desired
			? t("Turning on passwordless login means you will not be able to log in with a password — only a passkey. Keep at least two passkeys so a lost device never locks you out.")
			: t("Password login will be allowed for your account again.")));
		modal.actions.appendChild(primary(desired ? t("Turn on passwordless login") : t("Turn off passwordless login"), function () {
			modal.close();
			setPortalStatus(t("Confirming it's you…"), "pending");
			engine.call(METHODS.setPasskeyOnly, { enabled: !!desired }).then(function () {
				setPortalStatus(desired ? t("Passwordless login is on.") : t("Passwordless login is off."), "success");
				render();
			}).catch(function (err) {
				if (err && err.code === "user_cancelled") {
					setPortalStatus("");
					render();
					return;
				}
				setPortalStatus((err && err.message) || t("Couldn't change passwordless login."), "error");
				render();
			});
		}));
		modal.actions.appendChild(link(t("Cancel"), modal.close));
		modal.open();
	}
	function emptyState() {
		var w = el("div", "passkey-empty");
		w.appendChild(el("h4", "passkey-empty-title", t(M.COPY.emptyTitle)));
		w.appendChild(el("p", "passkey-empty-body", t(M.COPY.emptyBody)));
		var b = primary(t(M.COPY.addButton), addPasskey); b.classList.add("passkey-empty-cta");
		w.appendChild(b); return w;
	}
	function addRow() {
		var row = el("div", "passkey-card-add-row");
		row.appendChild(primary(t(M.COPY.addButton), addPasskey));
		// Reload for changes made on another device while the page is open.
		row.appendChild(link(t("Reload"), function () { render(); }));
		return row;
	}
	function cardEl(vm) {
		var li = el("li", "passkey-card" + (vm.enabled ? "" : " passkey-card-disabled")); li.setAttribute("data-name", vm.name);
		var g = el("span", "passkey-card-glyph");
		g.setAttribute("aria-hidden", "true");
		g.innerHTML = C.iconSvg("key", "icon");
		li.appendChild(g);
		var main = el("div", "passkey-card-main");
		var lr = el("div", "passkey-card-labelrow");
		var le = el("span", "passkey-card-label", vm.label);
		le.setAttribute("title", vm.label);
		lr.appendChild(le);
		var badge = el("span", "passkey-badge passkey-badge-" + (vm.badge.synced ? "synced" : "device"), t(vm.badge.key));
		badge.setAttribute("title", t(vm.badge.hintKey)); lr.appendChild(badge);
		if (!vm.enabled) lr.appendChild(el("span", "passkey-badge passkey-badge-disabled", t(M.COPY.disabledBadge)));
		main.appendChild(lr);
		var meta = el("div", "passkey-card-meta");
		meta.appendChild(el("span", "passkey-card-provider", vm.hasProvider ? vm.providerName : t(vm.unknownProviderKey)));
		meta.appendChild(el("span", "passkey-card-created", t(M.COPY.createdLabel) + ": " + fmtDate(vm.created)));
		meta.appendChild(el("span", "passkey-card-lastused", vm.lastUsed ? t(M.COPY.lastUsedLabel) + ": " + fmtDate(vm.lastUsed) : t(M.COPY.lastUsedNever)));
		main.appendChild(meta);
		if (vm.flagged) {
			var fb = el("div", "passkey-card-flagged", t(M.COPY.flaggedBanner));
			fb.setAttribute("role", "alert");
			main.appendChild(fb);
		}
		li.appendChild(main);
		var actions = el("div", "passkey-card-actions");
		actions.appendChild(iconBtn("passkey-rename", "pencil", vm.a11y.rename, function () { renameCard(vm); }));
		actions.appendChild(iconBtn("passkey-delete", "trash", vm.a11y.del, function () { deleteCard(vm); }));
		li.appendChild(actions);
		return li;
	}

	function renameCard(vm) {
		var modal = buildModal({ title: t("Rename passkey") });
		var input = document.createElement("input");
		input.type = "text";
		input.className = "form-control";
		input.value = vm.label;
		input.setAttribute("aria-label", t(M.COPY.renamePrompt));
		modal.body.appendChild(el("label", "", t(M.COPY.renamePrompt)));
		modal.body.appendChild(input);
		modal.actions.appendChild(primary(t("Save"), function () {
			modal.close();
			setPortalStatus(t("Renaming passkey…"), "pending");
			post(METHODS.rename, { name: vm.name, label: input.value }).then(function (res) {
				if (!res || !res.ok) throw new Error(C.serverMessages(res && res.body) || t("Couldn't rename the passkey."));
				setPortalStatus(t("Passkey renamed."), "success");
				render();
			}).catch(function (err) {
				setPortalStatus((err && err.message) || t("Couldn't rename the passkey."), "error");
			});
		}));
		modal.actions.appendChild(link(t("Cancel"), modal.close));
		modal.open();
		setTimeout(function () { input.focus(); }, 0);
	}

	function deleteCard(vm) {
		var modal = buildModal({ title: t(M.COPY.deleteConfirmTitle) });
		modal.body.appendChild(el("p", "", M.format(t(M.COPY.deleteConfirmBody), [vm.label])));
		modal.actions.appendChild(primary(t(M.COPY.deleteConfirmCta), function () {
			modal.close();
			setPortalStatus(t("Confirming it's you…"), "pending");
			var H = window.frappe && window.frappe.passkeys && window.frappe.passkeys.headless;
			if (!H || typeof H.removeCredential !== "function") {
				setPortalStatus(t("Couldn't remove the passkey."), "error");
				return;
			}
			H.removeCredential(vm.name).then(function () {
				setPortalStatus(t("Passkey removed."), "success"); render();
			}).catch(function (err) {
				if (err && err.code === "user_cancelled") { setPortalStatus(""); return; }
				setPortalStatus((err && err.message) || t("Couldn't remove the passkey."), "error");
			});
		}));
		modal.actions.appendChild(link(t("Cancel"), modal.close));
		modal.open();
	}

	// Registration is frappe.passkeys.headless.register, the same path a custom UI uses.
	function addPasskey(opts) {
		opts = opts || {};
		function done(ok) { if (typeof opts.onResult === "function") opts.onResult(ok); }
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
			setPortalStatus(t("This browser can't create passkeys."), "error");
			done(false);
			return;
		}
		var H = window.frappe && window.frappe.passkeys && window.frappe.passkeys.headless;
		if (!H) {
			setPortalStatus(t(M.COPY.addFailed), "error");
			done(false);
			return;
		}
		setPortalStatus(t("Follow your device's prompt to add a passkey…"), "pending");
		H.register({ flow: "explicit" }).then(function () {
			setPortalStatus(t("Passkey added."), "success");
			render();
			done(true);
		}, function (err) {
			setPortalStatus(t(err && err.code === "already_registered" ? M.COPY.alreadyRegistered : M.COPY.addFailed), "error");
			done(false);
		});
	}

	// ------------------------------------------------ enforcement + nudge boot
	// One capability probe; enforcement outranks the nudge. This runs on every
	// authenticated portal page, so a portal-only user can't skip it by avoiding /passkeys.
	function maybeEnforceOrNudge() {
		var b = (window.frappe && frappe.boot && frappe.boot.passkeys) || null;
		if (!b || b.enabled === false) return;
		C.detectCapabilities({ window: window }).then(function (caps) {
			var clientCaps = { supported: caps.supported, uvpaa: caps.uvpaa, hybrid: caps.hybrid };
			var enf = M.enforcementDecision(b, clientCaps);
			if (enf.show) {
				if (enf.notifyAdmin) reportIncapableOnce();
				if (enf.variant === "enforce") { showEnforceModal(b, enf); return; }
				// incapable + Degrade ⇒ the standard, non-blocking nudge banner
				renderNudgeBanner();
				return;
			}
			maybeNudgeBanner(b, clientCaps);
		}).catch(function () {});
	}

	function recordEnforcement(event) {
		return post(METHODS.recordEnforcement, { event: event });
	}
	var _recordSessionEvent = M.createSessionEventRecorder(getSessionStorage());
	function recordEnforcementDefer(b, enf) {
		var user = (window.frappe && window.frappe.session && window.frappe.session.user) || "current";
		var verdict = Object.assign({}, (b && b.enforcement) || {}, {
			graceRemaining: enf && enf.graceRemaining,
		});
		var key = M.enforcementDeferKey(user, verdict);
		return _recordSessionEvent(key, function () {
			return recordEnforcement(M.ENFORCE_EVENTS.DEFER).then(function (res) {
				if (!res || !res.ok) throw new Error("record_enforcement_failed");
				return res;
			});
		}).catch(function () {});
	}
	var _incapableReported = false;
	function reportIncapableOnce() {
		if (_incapableReported) return;
		_incapableReported = true;
		recordEnforcement(M.ENFORCE_EVENTS.INCAPABLE).catch(function () {});
	}

	// The post-login enforcement interstitial. Blocking ⇒ a static modal whose only exits
	// are enrolling, the incapable escape and sign-out.
	function showEnforceModal(b, enf) {
		var modal = buildModal({
			title: t(M.COPY.enforceTitle),
			static: enf.blocking === true,
			// Esc on a non-blocking gate is "Remind me later": it spends one grace login.
			// `_settled` stops a double count after the explicit link.
			onClose: function () {
				if (!enf.blocking && !modal._settled) { modal._settled = true; recordEnforcementDefer(b, enf); }
			},
		});
		modal.body.appendChild(el("p", "", t(M.COPY.enforceBody)));
		modal.actions.appendChild(primary(t(M.COPY.nudgeCta), function () { enforceCreate(modal); }));
		if (!enf.blocking) {
			var later = M.format(t(M.COPY.enforceRemindLater), [enf.graceRemaining]);
			modal.actions.appendChild(link(later, function () {
				recordEnforcementDefer(b, enf);
				modal._settled = true;
				modal.close();
			}));
		} else {
			// Only Block + Notify Admin actually notifies an administrator.
			var notifiesAdmin = ((b && b.enforcement) || {}).incapable_policy === "block_notify";
			var escapeLabel = notifiesAdmin ? M.COPY.enforceContactAdmin : M.COPY.enforceCantSetUp;
			modal.actions.appendChild(link(t(escapeLabel), function () { onEnforceCantSetUp(b, modal); }));
			modal.actions.appendChild(link(t(M.COPY.enforceSignOut), signOut));
		}
		modal.open();
	}

	function enforceCreate(modal) {
		// Keep a blocking modal open until enrollment actually succeeds (a cancelled
		// OS sheet must not dismiss a required gate).
		addPasskey({ onResult: function (ok) { if (ok) { modal._settled = true; modal.close(); } } });
	}

	// The blocking gate's escape: record it, then honor the incapable-device policy —
	// Degrade lets them proceed (re-prompted next page), Block + Notify Admin alerts the
	// admin and keeps the gate up with a notice.
	function onEnforceCantSetUp(b, modal) {
		reportIncapableOnce();
		var enf = (b && b.enforcement) || {};
		if (enf.incapable_policy === "block_notify") {
			modal.body.innerHTML = "";
			var notice = el("p", "", t(M.COPY.enforceBlockedNotice));
			notice.setAttribute("role", "alert");
			modal.body.appendChild(notice);
			modal.actions.innerHTML = "";
			modal.actions.appendChild(primary(t(M.COPY.enforceRetry), function () { enforceCreate(modal); }));
			modal.actions.appendChild(link(t(M.COPY.enforceSignOut), signOut));
		} else {
			modal._settled = true;
			modal.close();
		}
	}

	// ------------------------------------------------------- portal nudge banner
	// A dismissible inline banner, never a modal. `caps` may come from maybeEnforceOrNudge.
	function maybeNudgeBanner(b, caps) {
		b = b || (window.frappe && frappe.boot && frappe.boot.passkeys) || null;
		if (!b) return;
		function decide(c) {
			var d = M.nudgeDecision(b, { supported: c.supported, uvpaa: c.uvpaa }, Date.now());
			if (d.showNudge) renderNudgeBanner();
		}
		if (caps) { decide(caps); return; }
		C.detectCapabilities({ window: window }).then(decide).catch(function () {});
	}
	function renderNudgeBanner() {
		// /passkeys is the enrolment page itself: its empty state already offers the add.
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
		acts.appendChild(primary(t(M.COPY.nudgeCta), function () { location.href = "/passkeys"; }));
		acts.appendChild(link(t(M.COPY.nudgeLater), function () { recordNudge(M.NUDGE_EVENTS.DECLINED); bar.remove(); }));
		// Opt-out is permanent, so the banner stays until the server has saved it; a
		// failure is shown in place and the buttons stay usable for a retry.
		acts.appendChild(link(t(M.COPY.nudgeNever), function () {
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

	// Resolves the response, or null on a transport failure (never rejects).
	function recordNudge(event) {
		return post(METHODS.recordNudge, { event: event }).catch(function () { return null; });
	}

	// --------------------------------------------------------------- utils
	function announce(msg) { C.announce(document, msg); }
	function getSessionStorage() { try { return window.sessionStorage || null; } catch (e) { return null; } }
	function signOut() { window.location.href = "/api/method/logout"; }
	function setPortalStatus(msg, kind) {
		if (!statusRoot && mountRoot) {
			statusRoot = el("div", "passkey-portal-status");
			statusRoot.id = "passkey-portal-status";
			statusRoot.setAttribute("aria-live", "polite");
			if (mountRoot.parentNode && typeof mountRoot.parentNode.insertBefore === "function") {
				mountRoot.parentNode.insertBefore(statusRoot, mountRoot);
			}
		}
		if (!statusRoot) { if (msg) announce(msg); return; }
		if (!msg) {
			statusRoot.hidden = true;
			statusRoot.className = "passkey-portal-status";
			statusRoot.textContent = "";
			return;
		}
		statusRoot.hidden = false;
		statusRoot.className = "passkey-portal-status passkey-portal-status--" + (kind || "pending");
		statusRoot.setAttribute("role", kind === "error" ? "alert" : "status");
		statusRoot.textContent = msg;
	}
	function el(tag, cls, text) {
		var n = document.createElement(tag);
		if (cls) n.className = cls;
		if (text != null) n.textContent = text;
		return n;
	}
	function primary(label, on) {
		var b = document.createElement("button");
		b.type = "button";
		b.className = "btn btn-primary btn-sm passkey-btn";
		b.textContent = label;
		b.addEventListener("click", on);
		return b;
	}
	function link(label, on) {
		var b = document.createElement("button");
		b.type = "button";
		b.className = "btn btn-link btn-sm passkey-btn";
		b.textContent = label;
		b.addEventListener("click", on);
		return b;
	}
	function iconBtn(cls, iconName, name, on) {
		var b = document.createElement("button");
		b.type = "button";
		b.className = "btn btn-xs btn-default passkey-icon-btn " + cls;
		b.setAttribute("aria-label", name); b.setAttribute("title", name);
		var g = el("span", "passkey-icon");
		g.setAttribute("aria-hidden", "true");
		g.innerHTML = C.iconSvg(iconName, "icon icon-sm");
		b.appendChild(g);
		b.addEventListener("click", on); return b;
	}
	function fmtDate(v) {
		if (!v) return "—";
		try {
			if (window.frappe && frappe.datetime && frappe.datetime.str_to_user) return frappe.datetime.str_to_user(v);
		} catch (e) {
			/* fall back to the raw value */
		}
		return String(v);
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
