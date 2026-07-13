// passkey_portal.bundle.js — the portal /passkeys page component + the portal
// enrollment-nudge banner. Delivered via web_include_js on
// authenticated portal pages when a passkey mode is enabled (the shim gates it).
// Loaded AFTER passkey_common.bundle.js
// (frappe.passkeys_common) and passkey_manage_common.bundle.js
// (frappe.passkeys_manage_common). Destination on core merge: frappe/public/js/
// frappe/passkey/portal.js + frappe/www/passkeys.js.
//
// Portal pages do NOT ship frappe.ui.Dialog or the desk confirm bundle, so this
// file builds:
//   * its own confirm engine from the node-tested pure C.createConfirmEngine,
//     wired to a self-contained, a11y-correct modal, and
//   * a compact card renderer over the pure passkey_manage_common view-models.
// The card DOM differs from the desk bundle only in its framework glue.
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
	var isPasskeyPage = !!mountRoot;

	// ------------------------------------------------------------------ transport
	function post(method, body, headers) {
		return fetch("/api/method/" + method, {
			method: "POST",
			headers: jsonHeaders(headers),
			credentials: "same-origin",
			body: JSON.stringify(body || {}),
		}).then(function (resp) {
			return resp.json().catch(function () { return null; }).then(function (json) {
				return { ok: resp.ok, status: resp.status, body: json };
			});
		});
	}
	function jsonHeaders(extra) {
		var h = { "Content-Type": "application/json", Accept: "application/json" };
		var f = window.frappe;
		var token = f && (f.csrf_token || (f.boot && f.boot.csrf_token) || (f.session && f.session.csrf_token));
		if (token && token !== "None") h["X-Frappe-CSRF-Token"] = token;
		if (extra) for (var k in extra) if (extra.hasOwnProperty(k)) h[k] = extra[k];
		return h;
	}
	function unwrap(body) { return C.unwrapMessage(body); }

	// -------------------------------------------------------- self-contained modal
	// role=dialog + aria-modal + focus trap + Esc + focus return. Mirrors the
	// login bundle's buildDialog; portal has no frappe.ui.Dialog.
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
			if (e.key === "Escape" && !cfg.static) { e.preventDefault(); close(); return; }
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
	// The portal's frappe.passkeys.confirm/call, built from the pure engine + a
	// portal modal adapter (chooseMethod / collectPassword). Used for the delete
	// sudo gate.
	function makeConfirmUI() {
		var modal = null;
		return {
			chooseMethod: function (opts) {
				return new Promise(function (resolve, reject) {
					modal = buildModal({ title: t("Confirm it's you"), onClose: function () { if (!modal._settled) reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, t("Confirmation was cancelled."))); } });
					modal.body.appendChild(el("p", "", t("Confirm to manage your passkeys.")));
					var pk = primary(t("Confirm with passkey"), function () { resolve("passkey"); });
					modal.actions.appendChild(pk);
					if (opts.canPassword) modal.actions.appendChild(link(t("Use your password instead"), function () { resolve("password"); }));
					modal.actions.appendChild(link(t("Cancel"), function () { modal._settled = false; modal.close(); }));
					modal.open();
				});
			},
			collectPassword: function () {
				return new Promise(function (resolve) {
					if (!modal) modal = buildModal({ title: t("Confirm it's you") });
					modal.body.innerHTML = "";
					var lbl = el("label", "", t("Confirm your password to continue.")); lbl.setAttribute("for", "passkey-portal-pw");
					var input = document.createElement("input");
					input.type = "password"; input.id = "passkey-portal-pw"; input.className = "form-control"; input.autocomplete = "current-password";
					modal.body.appendChild(lbl); modal.body.appendChild(input);
					modal.actions.innerHTML = "";
					modal.actions.appendChild(primary(t("Confirm"), function () { var v = input.value; input.value = ""; resolve(v); }));
					input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); var v = input.value; input.value = ""; resolve(v); } });
					setTimeout(function () { input.focus(); }, 0);
				});
			},
			announce: function (m) { announce(m); },
			busy: function () {},
			passwordError: function (m) { announce(m); },
			done: function () { if (modal) { modal._settled = true; modal.close(); } },
			close: function () { if (modal) { modal._settled = true; modal.close(); } },
		};
	}
	function runGesture(optionsJSON) {
		if (!navigator.credentials || typeof navigator.credentials.get !== "function") {
			var e = new Error("not supported"); e.name = "NotSupportedError"; return Promise.reject(e);
		}
		var pk = C.parseRequestOptionsFromJSON(optionsJSON);
		return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
			if (!cred) { var err = new Error("no credential"); err.name = "NotAllowedError"; throw err; }
			return C.authAssertionToJSON(cred);
		});
	}
	var engine = C.createConfirmEngine({ post: post, runGesture: runGesture, ui: makeConfirmUI, translate: t });
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
			creds.forEach(function (cred) { list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map }))); });
			mountRoot.appendChild(list);
			mountRoot.appendChild(addRow());
			mountRoot.appendChild(passkeyOnlyRow(creds, payload)); // passwordless-login switch
		});
	}

	// the per-user passwordless-login switch. Current value rides the list
	// payload (server-authoritative), boot as fallback; OFF when neither ships it.
	// Disabled with no usable (enabled) passkey — enabling needs a passkey grant.
	function isPasskeyOnly(payload) {
		if (payload && payload.passkey_only_login !== undefined) return !!payload.passkey_only_login;
		var b = (window.frappe && frappe.boot && frappe.boot.passkeys) || null;
		return !!(b && b.passkey_only_login);
	}
	function passkeyOnlyRow(creds, payload) {
		var enabledCount = 0;
		creds.forEach(function (c) { if (M.credentialViewModel(c).enabled) enabledCount += 1; });
		var current = isPasskeyOnly(payload);
		var row = el("div", "passkey-only-row");
		var main = el("div", "passkey-only-main");
		main.appendChild(el("div", "passkey-only-label", t(M.COPY.passkeyOnlyLabel)));
		main.appendChild(el("div", "passkey-only-help", t(M.COPY.passkeyOnlyHelp)));
		row.appendChild(main);
		var toggle = document.createElement("input");
		toggle.type = "checkbox"; toggle.className = "passkey-only-toggle"; toggle.checked = current;
		toggle.setAttribute("role", "switch"); toggle.setAttribute("aria-checked", current ? "true" : "false");
		toggle.setAttribute("aria-label", t(M.COPY.passkeyOnlyLabel));
		if (enabledCount === 0) { toggle.disabled = true; toggle.setAttribute("title", t(M.COPY.passkeyOnlyHelp)); }
		toggle.addEventListener("change", function () {
			var desired = toggle.checked;
			toggle.checked = current; // don't flip until the sudo-gated call confirms
			confirmPasskeyOnly(desired, current);
		});
		row.appendChild(toggle);
		return row;
	}
	// Sudo-gated: confirm + single-use PASSKEY grant only. engine.call runs
	// the 401 confirm dance; the boolean {enabled} payload matches the fingerprint
	// the server binds the grant to ({"enabled": <bool>}). Mirrors deleteCard's flow.
	function confirmPasskeyOnly(desired, current) {
		if (desired === current) return;
		var modal = buildModal({ title: desired ? t("Turn on passwordless login?") : t("Turn off passwordless login?") });
		modal.body.appendChild(el("p", "", desired
			? t("Turning on passwordless login means you will not be able to log in with a password — only a passkey. Keep at least two passkeys so a lost device never locks you out.")
			: t("Password login will be allowed for your account again.")));
		modal.actions.appendChild(primary(desired ? t("Turn on passwordless login") : t("Turn off passwordless login"), function () {
			modal.close();
			announce(t("Confirming it's you…"));
			engine.call(METHODS.setPasskeyOnly, { enabled: !!desired }).then(function () {
				announce(desired ? t("Passwordless login is on.") : t("Passwordless login is off."));
				render();
			}).catch(function (err) {
				if (err && err.code === "user_cancelled") { render(); return; }
				announce((err && err.message) || t("Couldn't change passwordless login."));
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
		// Reload affordance (parity with the desk manager dialog): re-fetch the list for
		// the "changed on another device while the page stayed open" case. render()
		// re-runs list_credentials.
		row.appendChild(link(t("Reload"), function () { render(); }));
		return row;
	}
	function cardEl(vm) {
		var li = el("li", "passkey-card" + (vm.enabled ? "" : " passkey-card-disabled")); li.setAttribute("data-name", vm.name);
		var g = el("span", "passkey-card-glyph"); g.setAttribute("aria-hidden", "true"); g.innerHTML = C.iconSvg("key", "icon"); li.appendChild(g);
		var main = el("div", "passkey-card-main");
		var lr = el("div", "passkey-card-labelrow");
		var le = el("span", "passkey-card-label", vm.label); le.setAttribute("title", vm.label); lr.appendChild(le);
		var badge = el("span", "passkey-badge passkey-badge-" + (vm.badge.synced ? "synced" : "device"), t(vm.badge.key));
		badge.setAttribute("title", t(vm.badge.hintKey)); lr.appendChild(badge);
		if (!vm.enabled) lr.appendChild(el("span", "passkey-badge passkey-badge-disabled", t(M.COPY.disabledBadge)));
		main.appendChild(lr);
		var meta = el("div", "passkey-card-meta");
		meta.appendChild(el("span", "passkey-card-provider", vm.hasProvider ? vm.providerName : t(vm.unknownProviderKey)));
		meta.appendChild(el("span", "passkey-card-created", t(M.COPY.createdLabel) + ": " + fmtDate(vm.created)));
		meta.appendChild(el("span", "passkey-card-lastused", vm.lastUsed ? t(M.COPY.lastUsedLabel) + ": " + fmtDate(vm.lastUsed) : t(M.COPY.lastUsedNever)));
		main.appendChild(meta);
		if (vm.flagged) { var fb = el("div", "passkey-card-flagged", t(M.COPY.flaggedBanner)); fb.setAttribute("role", "alert"); main.appendChild(fb); }
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
		input.type = "text"; input.className = "form-control"; input.value = vm.label; input.setAttribute("aria-label", t(M.COPY.renamePrompt));
		modal.body.appendChild(el("label", "", t(M.COPY.renamePrompt)));
		modal.body.appendChild(input);
		modal.actions.appendChild(primary(t("Save"), function () {
			post(METHODS.rename, { name: vm.name, label: input.value }).then(function (res) {
				modal.close();
				if (res && res.ok) { announce(t("Passkey renamed.")); render(); }
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
			announce(t("Confirming it's you…"));
			// sudo-gated: engine.call catches the 401 contract + runs the confirm modal.
			engine.call(METHODS.del, { name: vm.name }).then(function () {
				announce(t("Passkey removed.")); render();
			}).catch(function (err) {
				if (err && err.code === "user_cancelled") return;
				announce((err && (err.message)) || t("Couldn't remove the passkey."));
			});
		}));
		modal.actions.appendChild(link(t("Cancel"), modal.close));
		modal.open();
	}

	// The add-passkey ceremony (begin + sudo dance + create + verify) is the shared
	// headless engine (frappe.passkeys.headless.register) — this card engine is a
	// CALLER of the same node-tested code path a custom UI uses; the wrapper is only
	// the portal's DOM (announce / render / onResult). The sudo dance rides
	// frappe.passkeys.confirm, which this bundle set to `engine.confirm` above.
	function addPasskey(opts) {
		opts = opts || {};
		function done(ok) { if (typeof opts.onResult === "function") opts.onResult(ok); }
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
			announce(t("This browser can't create passkeys.")); done(false); return;
		}
		var H = window.frappe && window.frappe.passkeys && window.frappe.passkeys.headless;
		if (!H) { announce(t(M.COPY.addFailed)); done(false); return; }
		announce(t("Follow your device's prompt to add a passkey…"));
		H.register({ flow: "explicit" }).then(function () {
			announce(t("Passkey added.")); render(); done(true);
		}, function (err) {
			announce(t(err && err.code === "already_registered" ? M.COPY.alreadyRegistered : M.COPY.addFailed));
			done(false);
		});
	}

	// ------------------------------------------------ enforcement + nudge boot
	// One capability probe drives both surfaces: the server enforcement verdict outranks
	// the nudge (a user MUST register), then the dismissible nudge banner for everyone
	// else. Enforcement on the portal must ride EVERY authenticated page (portal_nudge
	// shim delivers this bundle everywhere) so a portal-only user can't escape by never
	// opening /passkeys.
	function maybeEnforceOrNudge() {
		var b = (window.frappe && frappe.boot && frappe.boot.passkeys) || null;
		if (!b) return;
		C.detectCapabilities({ window: window }).then(function (caps) {
			var clientCaps = { supported: caps.supported, uvpaa: caps.uvpaa, hybrid: caps.hybrid };
			var enf = M.enforcementDecision(b, clientCaps);
			if (enf.show) {
				if (enf.notifyAdmin) reportIncapableOnce();
				if (enf.variant === "enforce") { showEnforceModal(b, enf); return; }
				// incapable + Degrade ⇒ the standard, non-blocking nudge banner
				maybeNudgeBanner(b, clientCaps);
				return;
			}
			maybeNudgeBanner(b, clientCaps);
		}).catch(function () {});
	}

	function recordEnforcement(event) {
		post(METHODS.recordEnforcement, { event: event }).catch(function () {}); // server owns grace
	}
	var _incapableReported = false;
	function reportIncapableOnce() {
		if (_incapableReported) return;
		_incapableReported = true;
		recordEnforcement(M.ENFORCE_EVENTS.INCAPABLE);
	}

	// The post-login ENFORCEMENT interstitial (portal). Blocking ⇒ a static modal
	// (no Esc / no backdrop dismiss); the only ways out are enrolling or the incapable
	// escape. Honest, guilt-free copy matching the desk gate.
	function showEnforceModal(b, enf) {
		var modal = buildModal({
			title: t(M.COPY.enforceTitle),
			static: enf.blocking === true,
			// Esc dismiss of a NON-BLOCKING gate = "Remind me later": spend one grace login
			// exactly once (mirrors the confirm modal's onClose + _settled guard). The explicit
			// link sets `_settled` before closing, so this fires only on an UNACTED Esc dismissal —
			// the route no click handler covers. A blocking gate is static (Esc suppressed) with
			// no grace left to spend, so it records nothing.
			onClose: function () {
				if (!enf.blocking && !modal._settled) { modal._settled = true; recordEnforcement(M.ENFORCE_EVENTS.DEFER); }
			},
		});
		modal.body.appendChild(el("p", "", t(M.COPY.enforceBody)));
		modal.actions.appendChild(primary(t(M.COPY.nudgeCta), function () { enforceCreate(modal); }));
		if (!enf.blocking) {
			var later = M.format(t(M.COPY.enforceRemindLater), [enf.graceRemaining]);
			modal.actions.appendChild(link(later, function () {
				recordEnforcement(M.ENFORCE_EVENTS.DEFER); modal._settled = true; modal.close();
			}));
		} else {
			modal.actions.appendChild(link(t(M.COPY.enforceCantSetUp), function () { onEnforceCantSetUp(b, modal); }));
		}
		modal.open();
	}

	function enforceCreate(modal) {
		// Keep a blocking modal open until enrollment actually succeeds (a cancelled
		// OS sheet must not dismiss a required gate).
		addPasskey({ onResult: function (ok) { if (ok) { modal._settled = true; modal.close(); } } });
	}

	// "I can't set one up here": alert the admin, then honor the incapable-device policy
	// — Degrade lets them proceed (re-prompted next page), Block keeps the gate up with
	// an escalation notice.
	function onEnforceCantSetUp(b, modal) {
		reportIncapableOnce();
		var enf = (b && b.enforcement) || {};
		if (enf.incapable_policy === "block_notify") {
			modal.body.innerHTML = "";
			var notice = el("p", "", t(M.COPY.enforceBlockedNotice));
			notice.setAttribute("role", "alert");
			modal.body.appendChild(notice);
			modal.actions.innerHTML = "";
		} else {
			modal._settled = true;
			modal.close();
		}
	}

	// ------------------------------------------------------- portal nudge banner
	// A dismissible inline banner ("portal nudge banner") — never a modal. Caps may be
	// supplied by maybeEnforceOrNudge (one shared probe) or detected here.
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
		if (document.getElementById("passkey-portal-nudge")) return;
		var host = mountRoot || document.querySelector(".page_content, main, body");
		if (!host) return;
		post(METHODS.recordNudge, { event: M.NUDGE_EVENTS.SHOWN }).catch(function () {});
		var bar = el("div", "passkey-nudge-banner"); bar.id = "passkey-portal-nudge"; bar.setAttribute("role", "region"); bar.setAttribute("aria-label", t(M.COPY.nudgeTitle));
		bar.appendChild(el("strong", "passkey-nudge-title", t(M.COPY.nudgeTitle)));
		bar.appendChild(el("span", "passkey-nudge-copy", t(M.COPY.nudgeBody)));
		var acts = el("span", "passkey-nudge-acts");
		acts.appendChild(primary(t(M.COPY.nudgeCta), function () { if (mountRoot) addPasskey(); else location.href = "/passkeys"; }));
		acts.appendChild(link(t(M.COPY.nudgeLater), function () { post(METHODS.recordNudge, { event: M.NUDGE_EVENTS.DECLINED }).catch(function () {}); bar.remove(); }));
		acts.appendChild(link(t(M.COPY.nudgeNever), function () { post(METHODS.recordNudge, { event: M.NUDGE_EVENTS.OPT_OUT }).catch(function () {}); bar.remove(); }));
		bar.appendChild(acts);
		host.insertBefore(bar, host.firstChild);
	}

	// --------------------------------------------------------------- utils
	function announce(msg) { C.announce(document, msg); }
	function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
	function primary(label, on) { var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-primary btn-sm passkey-btn"; b.textContent = label; b.addEventListener("click", on); return b; }
	function link(label, on) { var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-link btn-sm passkey-btn"; b.textContent = label; b.addEventListener("click", on); return b; }
	function iconBtn(cls, iconName, name, on) {
		var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-xs btn-default passkey-icon-btn " + cls;
		b.setAttribute("aria-label", name); b.setAttribute("title", name);
		var g = el("span", "passkey-icon"); g.setAttribute("aria-hidden", "true"); g.innerHTML = C.iconSvg(iconName, "icon icon-sm"); b.appendChild(g);
		b.addEventListener("click", on); return b;
	}
	function fmtDate(v) { if (!v) return "—"; try { if (window.frappe && frappe.datetime && frappe.datetime.str_to_user) return frappe.datetime.str_to_user(v); } catch (e) {} return String(v); }

	// --------------------------------------------------------------- boot
	if (isPasskeyPage) render();
	maybeEnforceOrNudge();

	// Node-only test seam (UMD-lite, mirrors passkey_login.bundle.js): expose the
	// enforcement interstitial + modal builder so `node --test` can pin the defer-on-Esc
	// contract without a bench. No-op in the browser — `module` is undefined there.
	if (typeof module === "object" && module.exports) {
		module.exports = { showEnforceModal: showEnforceModal, buildModal: buildModal };
	}
})();
