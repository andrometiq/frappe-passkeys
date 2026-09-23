// passkey_desk.bundle.js — Desk credential management + enrollment nudges. Loads AFTER
// passkey_common, passkey_manage_common and passkey_confirm (frappe.passkeys.confirm/call).
//
// Publishes `frappe.passkeys.manage`:
//   renderCards(container, opts)        — the shared card component (own creds)
//   renderReadOnlyInventory(el, user)   — System-Manager view of another user
//   openManagerDialog()                 — the "My Passkeys" manager dialog
//   addPasskey(opts)                    — the registration ceremony (sudo-gated)
//   refresh()                           — re-fetch + repaint any live surface
//
// At Desk boot it runs the enforcement gate / nudge / conditional create / upsell from
// frappe.boot.passkeys. Pure decisions live in passkey_manage_common.bundle.js.
//
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	var M = window.frappe && window.frappe.passkeys_manage_common;
	if (!C || !M) return; // shared libs missing — fail safe, never throw on Desk boot

	var t = C.t;
	var METHODS = M.MANAGE_METHODS;

	// A pending conditionalCreate() holds a WebAuthn request open for the tab, so any
	// explicit ceremony throws "A request is already pending" until it is aborted.
	var _conditionalCreateAbort = null;
	function newAbortController() {
		return typeof AbortController === "function" ? new AbortController() : null;
	}
	function abortConditionalCreate() {
		if (_conditionalCreateAbort) {
			try { _conditionalCreateAbort.abort(); } catch (e) { /* noop */ }
			_conditionalCreateAbort = null;
		}
	}

	// ------------------------------------------------------------ AAGUID asset
	// Optional client provider snapshot; absent ⇒ {}.
	var _aaguidMap = null;
	function loadAaguidMap() {
		if (_aaguidMap) return Promise.resolve(_aaguidMap);
		return fetch("/assets/passkeys/aaguid-map.json", { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : {}; })
			.catch(function () { return {}; })
			.then(function (map) { _aaguidMap = map || {}; return _aaguidMap; });
	}

	// ---------------------------------------------------------------- transport
	// Raw fetch so we own the 401 retry-contract body. Resolves {ok, status, body} for any
	// status; rejects only on a transport failure.
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
		var token = f && (f.csrf_token || (f.session && f.session.csrf_token));
		if (token) h["X-Frappe-CSRF-Token"] = token;
		if (extra) for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k];
		return h;
	}
	function unwrap(body) { return C.unwrapMessage(body); }

	// -------------------------------------------------------------- sudo dance
	// A sudo-gated mutation: on the 401 contract run a passkeys.manage confirmation, then
	// retry once with the grant header.
	function guardedCall(method, args) {
		abortConditionalCreate();
		if (window.frappe && window.frappe.passkeys && window.frappe.passkeys.call) {
			return window.frappe.passkeys.call(method, args || {});
		}
		// confirm client absent — attempt the bare call so the server can 401.
		return post(method, args).then(function (res) {
			if (res && res.ok) return unwrap(res.body);
			throw new Error("confirmation_unavailable");
		});
	}

	// Seed a management sudo window before registration (begin→create→verify cannot ride
	// guardedCall's single retry).
	function ensureManageSudo() {
		abortConditionalCreate();
		if (window.frappe && window.frappe.passkeys && window.frappe.passkeys.confirm) {
			return window.frappe.passkeys.confirm(M.MANAGE_ACTION);
		}
		return Promise.reject(new Error("confirmation_unavailable"));
	}

	// ---------------------------------------------------------- registration
	// Add a passkey: sudo-gated begin, then a modal create() with credProps, then verify.
	function addPasskey(opts) {
		opts = opts || {};
		abortConditionalCreate();
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") {
			frappe.msgprint({ title: t("Passkeys unavailable"), message: t("This browser can't create passkeys."), indicator: "orange" });
			return Promise.reject(new Error("not_supported"));
		}
		return beginRegistration(false).then(function (begin) {
			var options;
			try {
				options = parseCreate(begin.options);
			} catch (e) { throw friendly("addFailed"); }
			// inject credProps for EVERY registration ceremony (py_webauthn
			// emits no extensions member; the tri-state stays Unknown without this).
			options.extensions = Object.assign({}, options.extensions || {}, { credProps: true });
			return navigator.credentials.create({ publicKey: options }).then(function (cred) {
				if (!cred) throw friendly("addFailed");
				var payload = C.registrationResponseToJSON(cred);
				return post(METHODS.verifyRegistration, {
					state_id: begin.state_id,
					credential: JSON.stringify(payload),
					label: opts.label || undefined,
				}).then(function (res) {
					if (!res || !res.ok) throw mapVerifyError(res);
					var data = unwrap(res.body) || {};
					fireSignal(data);
					return data;
				});
			}, function (err) { throw mapCreateError(err); });
		});
	}

	// begin_registration with the sudo dance. `retried` guards the single re-begin.
	function beginRegistration(retried) {
		return post(METHODS.beginRegistration, { flow: "explicit" }).then(function (res) {
			if (res && res.ok) return unwrap(res.body);
			var req = res && res.status === 401 && C.parseConfirmationRequired(res.body);
			if (req && !retried) {
				return ensureManageSudo().then(function () { return beginRegistration(true); });
			}
			throw mapVerifyError(res);
		});
	}

	function parseCreate(json) {
		var PKC = window.PublicKeyCredential;
		if (PKC && typeof PKC.parseCreationOptionsFromJSON === "function") {
			return PKC.parseCreationOptionsFromJSON(json);
		}
		// Minimal polyfill (challenge + user.id are the base64url members).
		var out = Object.assign({}, json);
		out.challenge = C.b64urlToBytes(json.challenge);
		if (json.user && json.user.id) out.user = Object.assign({}, json.user, { id: C.b64urlToBytes(json.user.id) });
		if (Array.isArray(json.excludeCredentials)) {
			out.excludeCredentials = json.excludeCredentials.map(function (c) {
				return { type: c.type || "public-key", id: C.b64urlToBytes(c.id), transports: c.transports };
			});
		}
		return out;
	}

	function mapCreateError(err) {
		var name = err && (err.name || err.code);
		if (name === "InvalidStateError") return friendly("alreadyRegistered");
		if (name === "NotAllowedError" || name === "AbortError") return friendly("addFailed", true);
		return friendly("addFailed");
	}
	function mapVerifyError(res) {
		var exc = res && res.body && res.body.exc_type;
		if (C.mapServerExcType(exc) === "ceremony_expired") return friendly("addExpired");
		return friendly("addFailed");
	}
	function friendly(copyKey, silent) {
		var e = new Error(copyKey);
		e.userMessage = t(M.COPY[copyKey] || copyKey);
		e.silent = !!silent;
		return e;
	}

	// ------------------------------------------------------------------ signals
	// Every signal below is strictly best-effort, fire-and-forget: guarded by a typeof check
	// (Firefox ships none of the Signal API), never awaited on any critical path, and its
	// promise is .catch()'d (Safari 26's never-settling bug can neither resolve nor reject).
	function fireSignal(data) {
		var rpId = (window.frappe && frappe.boot && frappe.boot.passkeys && frappe.boot.passkeys.rp_id) || location.hostname;
		M.signalCredentialState(window.PublicKeyCredential, data, rpId);
	}
	function refreshSignalsInSession() {
		post(METHODS.getSignalData, {}).then(function (res) {
			if (res && res.ok) fireSignal(unwrap(res.body));
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
		var loading = el("div", "passkey-cards-loading", t("Loading your passkeys…"));
		container.appendChild(loading);

		return Promise.all([post(METHODS.list, {}), loadAaguidMap()]).then(function (r) {
			container.innerHTML = "";
			var res = r[0];
			var map = r[1];
			if (!res || !res.ok) {
				container.appendChild(el("div", "passkey-cards-error", t("Couldn't load your passkeys.")));
				return;
			}
			var payload = unwrap(res.body) || {};
			var creds = payload.credentials || [];
			if (!creds.length) {
				container.appendChild(emptyState(opts));
				return;
			}
			var list = document.createElement("ul");
			list.className = "passkey-card-list";
			list.setAttribute("role", "list");
			creds.forEach(function (cred) {
				list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map, translate: t }), opts));
			});
			container.appendChild(list);
			container.appendChild(addButtonRow(opts));
			// the per-user passwordless-login switch. Own view only — never
			// on the System-Manager read-only inventory of another user.
			if (!opts.readOnly) container.appendChild(passkeyOnlyRow(creds, payload, opts));
		});
	}

	function emptyState(opts) {
		var wrap = el("div", "passkey-empty");
		wrap.appendChild(el("h4", "passkey-empty-title", t(M.COPY.emptyTitle)));
		wrap.appendChild(el("p", "passkey-empty-body", t(M.COPY.emptyBody)));
		var btn = primaryButton(t(M.COPY.addButton), function () { triggerAdd(opts); });
		btn.classList.add("passkey-empty-cta");
		wrap.appendChild(btn);
		return wrap;
	}

	function addButtonRow(opts) {
		var row = el("div", "passkey-card-add-row");
		row.appendChild(primaryButton(t(M.COPY.addButton), function () { triggerAdd(opts); }));
		return row;
	}

	function cardEl(vm, opts) {
		var li = document.createElement("li");
		li.className = "passkey-card" + (vm.enabled ? "" : " passkey-card-disabled");
		li.setAttribute("data-name", vm.name);

		var glyph = el("span", "passkey-card-glyph");
		glyph.setAttribute("aria-hidden", "true");
		glyph.innerHTML = C.iconSvg("key", "icon");
		li.appendChild(glyph);

		var main = el("div", "passkey-card-main");
		var labelRow = el("div", "passkey-card-labelrow");
		var labelEl = el("span", "passkey-card-label", vm.label);
		labelEl.setAttribute("title", vm.label);
		labelRow.appendChild(labelEl);
		// Synced / Device-bound badge with a TEXT equivalent.
		var badge = el("span", "passkey-badge passkey-badge-" + (vm.badge.synced ? "synced" : "device"), t(vm.badge.key));
		badge.setAttribute("title", t(vm.badge.hintKey));
		labelRow.appendChild(badge);
		if (!vm.enabled) labelRow.appendChild(el("span", "passkey-badge passkey-badge-disabled", t(M.COPY.disabledBadge)));
		main.appendChild(labelRow);

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

		if (!opts.readOnly) {
			var actions = el("div", "passkey-card-actions");
			actions.appendChild(iconButton("passkey-rename", "pencil", vm.a11y.rename, function () { renameCard(vm, opts); }));
			actions.appendChild(iconButton("passkey-delete", "trash", vm.a11y.del, function () { deleteCard(vm, opts); }));
			li.appendChild(actions);
		}
		return li;
	}

	// Inline rename (display-only, no sudo).
	function renameCard(vm, opts) {
		var d = new frappe.ui.Dialog({
			title: t("Rename passkey"),
			fields: [{ fieldname: "label", fieldtype: "Data", label: t(M.COPY.renamePrompt), reqd: 1, default: vm.label }],
			primary_action_label: t("Save"),
			primary_action: function (values) {
				post(METHODS.rename, { name: vm.name, label: values.label }).then(function (res) {
					d.hide();
					if (res && res.ok) { announce(t("Passkey renamed.")); refresh(opts); }
					else frappe.msgprint(t("Couldn't rename the passkey."));
				});
			},
		});
		d.show();
	}

	// Delete: confirm dialog + sudo gate. The client-side last-method
	// guard is advisory; the server enforces it authoritatively.
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
					var msg = (err && (err.userMessage || err.message)) || t("Couldn't remove the passkey.");
					// server last-method guard / other refusals surface here
					if (err && err.code === "user_cancelled") return; // silent on cancel
					frappe.msgprint({ title: t("Couldn't remove passkey"), message: escapeHtml(msg), indicator: "orange" });
				});
			},
		});
		d.show();
	}

	// Passwordless-login switch. The value comes from the list payload, else boot, else off.
	function isPasskeyOnly(payload) {
		if (payload && payload.passkey_only_login !== undefined) return !!payload.passkey_only_login;
		var b = boot();
		return !!(b && b.passkey_only_login);
	}

	function passkeyOnlyRow(creds, payload, opts) {
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
		toggle.setAttribute("role", "switch");
		toggle.setAttribute("aria-checked", current ? "true" : "false");
		toggle.setAttribute("aria-label", t(M.COPY.passkeyOnlyLabel));
		if (availability.disabled) {
			toggle.disabled = true;
			toggle.setAttribute("title", t(M.COPY.passkeyOnlyNeedsTwo));
		}
		toggle.addEventListener("change", function () {
			var desired = toggle.checked;
			// Don't optimistically flip — the change only takes effect once the
			// sudo-gated call confirms. Snap back until then.
			toggle.checked = current;
			confirmPasskeyOnly(desired, current, opts);
		});
		row.appendChild(toggle);
		return row;
	}

	// Needs a single-use PASSKEY grant; the server binds it to the {"enabled": <bool>} payload.
	function confirmPasskeyOnly(desired, current, opts) {
		if (desired === current) return;
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
				guardedCall(METHODS.setPasskeyOnly, { enabled: !!desired }).then(function () {
					announce(desired ? t("Passwordless login is on.") : t("Passwordless login is off."));
					refresh(opts);
				}).catch(function (err) {
					if (err && err.code === "user_cancelled") { refresh(opts); return; } // reset the toggle
					var msg = (err && (err.userMessage || err.message)) || t("Couldn't change passwordless login.");
					frappe.msgprint({ title: t("Couldn't change passwordless login"), message: escapeHtml(msg), indicator: "orange" });
					refresh(opts);
				});
			},
		});
		// Close / Esc / backdrop dismiss leaves the switch as it was — the toggle was
		// already snapped back to its current value before this dialog opened.
		d.show();
	}

	function triggerAdd(opts) {
		announce(t("Follow your device's prompt to add a passkey…"));
		addPasskey({}).then(function () {
			announce(t("Passkey added."));
			refresh(opts);
		}).catch(function (err) {
			if (err && err.silent) return; // user cancelled the OS sheet — no scolding
			if (err && err.code === "user_cancelled") return;
			var msg = (err && (err.userMessage || err.message)) || t(M.COPY.addFailed);
			frappe.msgprint({ title: t("Couldn't add passkey"), message: escapeHtml(msg), indicator: "orange" });
		});
	}

	// System-Manager read-only inventory of ANOTHER user, read from the DocType directly
	// (list_* returns only the session user's rows).
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
			loadAaguidMap(),
		]).then(function (r) {
			var creds = r[0] || [];
			var map = r[1];
			if (!creds.length) {
				container.appendChild(el("div", "passkey-cards-empty-admin", t("This user has no passkeys.")));
				return;
			}
			var list = document.createElement("ul");
			list.className = "passkey-card-list";
			list.setAttribute("role", "list");
			creds.forEach(function (cred) {
				list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map, translate: t }), { readOnly: true }));
			});
			container.appendChild(list);
			var link = document.createElement("a");
			link.className = "passkey-admin-link";
			link.href = "/app/webauthn-credential?user=" + encodeURIComponent(user);
			link.textContent = t("Manage in the WebAuthn Credential list");
			container.appendChild(link);
		});
	}

	// ------------------------------------------------ admin enforcement recovery
	// System-Manager enforcement recovery for ANOTHER user (exemption + grace reset). Every
	// endpoint re-checks only_for("System Manager"); this is convenience, not the boundary.
	function enfAdminCall(method, args) {
		return post(method, args || {}).then(function (res) {
			if (res && res.ok) return unwrap(res.body);
			throw new Error("enforcement_admin_call_failed");
		});
	}
	function enfAdminFail() {
		frappe.msgprint({ title: t("Passkeys"), message: t(M.COPY.enforceAdminFailed), indicator: "orange" });
	}
	function enfAdminBusy(actionsEl, on) {
		if (!actionsEl || !actionsEl.querySelectorAll) return;
		var btns = actionsEl.querySelectorAll("button");
		for (var i = 0; i < btns.length; i++) btns[i].disabled = !!on;
	}
	function renderEnforcementAdmin(container, user, bootObj) {
		if (!container) return;
		container.innerHTML = "";
		if (!M.shouldShowEnforcementAdmin(bootObj || boot())) return; // policy not enforcing
		return enfAdminCall(METHODS.getUserEnforcementAdmin, { user: user }).then(function (view) {
			paintEnforcementAdmin(container, user, view);
		}).catch(function () {
			container.innerHTML = ""; // read failed (permission / transport) — render nothing
		});
	}
	function paintEnforcementAdmin(container, user, view) {
		container.innerHTML = "";
		var vm = M.enforcementAdminViewModel(view);
		var wrap = el("div", "passkey-enforcement-admin");
		wrap.appendChild(el("div", "passkey-enforcement-admin-title text-muted", t(M.COPY.enforceAdminHeading)));

		var status = el("div", "passkey-enforcement-admin-status");
		status.appendChild(el("span", "indicator-pill " + vm.indicator.color));
		status.appendChild(el("span", "passkey-enforcement-admin-status-text", t(M.COPY[vm.indicator.textKey])));
		wrap.appendChild(status);

		var graceText = t(M.COPY.enforceAdminGrace)
			.replace("{0}", vm.graceUsed).replace("{1}", vm.graceTotal).replace("{2}", vm.graceRemaining);
		wrap.appendChild(el("div", "passkey-enforcement-admin-grace small text-muted", graceText));

		var actions = el("div", "passkey-enforcement-admin-actions");
		var exemptBtn = el("button", "btn btn-xs " + (vm.exemptButtonPrimary ? "btn-primary" : "btn-default"), t(M.COPY[vm.exemptButtonKey]));
		exemptBtn.setAttribute("type", "button");
		exemptBtn.addEventListener("click", function () {
			enfAdminBusy(actions, true);
			enfAdminCall(METHODS.setUserExemption, { user: user, exempt: vm.nextExemptValue }).then(function (nv) {
				paintEnforcementAdmin(container, user, nv);
				frappe.show_alert({
					message: t(nv.exempt ? M.COPY.enforceAdminExemptDone : M.COPY.enforceAdminUnexemptDone).replace("{0}", user),
					indicator: "green",
				});
			}).catch(function () { enfAdminBusy(actions, false); enfAdminFail(); });
		});
		actions.appendChild(exemptBtn);

		var resetBtn = el("button", "btn btn-xs btn-default", t(M.COPY.enforceAdminReset));
		resetBtn.setAttribute("type", "button");
		if (vm.resetDisabled) resetBtn.disabled = true;
		resetBtn.addEventListener("click", function () {
			enfAdminBusy(actions, true);
			enfAdminCall(METHODS.resetEnforcementGrace, { user: user }).then(function (nv) {
				paintEnforcementAdmin(container, user, nv);
				frappe.show_alert({
					message: t(M.COPY.enforceAdminResetDone).replace("{0}", nv.grace_total),
					indicator: "green",
				});
			}).catch(function () { enfAdminBusy(actions, false); enfAdminFail(); });
		});
		actions.appendChild(resetBtn);

		wrap.appendChild(actions);
		container.appendChild(wrap);
	}

	// ---------------------------------------------------------- navbar dialog
	var _managerDialog = null;
	function isEscapeEvent(e) {
		return e && (e.key === "Escape" || e.key === "Esc" || e.code === "Escape" || e.keyCode === 27 || e.which === 27);
	}
	function wireManagerDialogEsc(d) {
		if (!d || d._passkeyEscWired) return;
		d._passkeyEscWired = true;
		document.addEventListener("keydown", function (e) {
			if (!isEscapeEvent(e) || !d.$wrapper || !d.$wrapper.is(":visible")) return;
			var visibleModals = $(".modal:visible").get();
			if (visibleModals.length && visibleModals[visibleModals.length - 1] !== d.$wrapper.get(0)) return;
			e.preventDefault();
			d.hide();
		}, true);
	}
	function openManagerDialog() {
		if (_managerDialog) {
			wireManagerDialogEsc(_managerDialog);
			_managerDialog.show();
			// Re-render on every open: $wrapper.is(":visible") is false mid fade-in.
			if (_managerDialog._passkeyRoot) refresh({ root: _managerDialog._passkeyRoot });
			return _managerDialog;
		}
		var d = new frappe.ui.Dialog({ title: t("My Passkeys"), size: "large" });
		_managerDialog = d;
		wireManagerDialogEsc(d);
		var body = d.$body ? d.$body.get(0) : null;
		if (body) {
			var root = el("div", "passkey-manager");
			body.appendChild(root);
			d._passkeyRoot = root;
			addReloadAction(d, root);
			renderCards(root, { dialog: d, root: root });
		}
		d.show();
		return d;
	}

	// A refresh action for changes made on another device while the dialog is open.
	function addReloadAction(d, root) {
		if (!d || typeof d.add_custom_action !== "function") return;
		d.add_custom_action(t("Reload"), function () { refresh({ root: root }); });
	}

	function refresh(opts) {
		opts = opts || {};
		if (opts.root) return renderCards(opts.root, opts);
		if (_managerDialog && _managerDialog._passkeyRoot && _managerDialog.$wrapper && _managerDialog.$wrapper.is(":visible")) {
			renderCards(_managerDialog._passkeyRoot, { root: _managerDialog._passkeyRoot });
		}
		// User-form section refresh is handled by user_passkeys.js via its own root.
		document.dispatchEvent(new CustomEvent("passkey:changed"));
	}

	// ============================================================ nudges
	function boot() { return (window.frappe && frappe.boot && frappe.boot.passkeys) || null; }

	function markNudgeEvaluated() {
		// Marks that the boot decision ran, whatever the outcome, so specs can assert absence.
		try {
			document.documentElement.setAttribute("data-passkeys-nudge-evaluated", "true");
		} catch (e) { /* test signal only */ }
	}

	function maybeNudge() {
		var b = boot();
		if (!b) return; // no bootinfo contract yet ⇒ safe no-op (server dependency)
		return Promise.all([C.detectCapabilities({ window: window }), probeConditionalCreate()]).then(function (r) {
			var caps = r[0];
			var clientCaps = {
				supported: caps.supported,
				uvpaa: caps.uvpaa,
				hybrid: caps.hybrid,
				conditionalCreate: r[1] === true, // certain-true only
			};
			// Enforcement outranks the nudge/upsell entirely: the server verdict says the
			// user MUST register. The client's only job is device capability.
			var enf = M.enforcementDecision(b, clientCaps);
			if (enf.show) {
				if (enf.notifyAdmin) reportIncapableOnce(); // Block + Notify: alert the admin
				if (enf.variant === "enforce") { showEnforceDialog(b, enf); return; }
				// incapable + Degrade ⇒ the standard, non-blocking nudge instead of a dead-end
				showNudgeDialog(b, false);
				return;
			}
			// post-hybrid upsell takes precedence (the login just happened over hybrid)
			var upsell = M.upsellDecision(b, clientCaps, storageGet, Date.now());
			clearUpsellFlag();
			if (upsell.showUpsell) return showNudgeDialog(b, true);
			// silent conditional create (no dialog) — Firefox has none, so the visible
			// nudge is its whole story
			var d = M.nudgeDecision(b, clientCaps, Date.now());
			if (d.allowConditionalCreate) return conditionalCreate(function () { if (d.showNudge) showNudgeDialog(b, false); });
			if (d.showNudge) showNudgeDialog(b, false);
		}).then(markNudgeEvaluated, markNudgeEvaluated);
	}

	// getClientCapabilities().conditionalCreate — the only reliable signal for the
	// silent upgrade. Unknown / absent ⇒ false (silent create must be certain).
	function probeConditionalCreate() {
		var PKC = window.PublicKeyCredential;
		if (!PKC || typeof PKC.getClientCapabilities !== "function") return Promise.resolve(false);
		return Promise.resolve().then(function () { return PKC.getClientCapabilities(); })
			.then(function (caps) { return !!(caps && caps.conditionalCreate); })
			.catch(function () { return false; });
	}

	function showNudgeDialog(b, isUpsell) {
		var titleKey = isUpsell ? M.COPY.upsellTitle : M.COPY.nudgeTitle;
		var bodyKey = isUpsell ? M.COPY.upsellBody : M.COPY.nudgeBody;
		var d = new frappe.ui.Dialog({ title: t(titleKey), size: "small" });
		var act = function (event) { if (d._acted) return; d._acted = true; recordNudge(event); d.hide(); };
		var body = d.$body ? d.$body.get(0) : null;
		var optingOut = false, error = null;
		// Opt-out is permanent, so the dialog stays until the server has saved it; a
		// failure is shown in place and the buttons stay usable for a retry.
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
		if (body) {
			body.appendChild(el("p", "passkey-nudge-body", t(bodyKey)));
			var actions = el("div", "passkey-nudge-actions");
			actions.appendChild(primaryButton(t(M.COPY.nudgeCta), function () {
				// CTA runs under the fresh-login sudo window — zero re-prompt.
				d._acted = true; d.hide(); triggerAdd({});
			}));
			actions.appendChild(linkButton(t(M.COPY.nudgeLater), function () { act(M.NUDGE_EVENTS.DECLINED); }));
			actions.appendChild(linkButton(t(M.COPY.nudgeNever), optOut));
			body.appendChild(actions);
		}
		// Esc / backdrop dismiss = "Not now" semantics: the modal's hide event
		// is the one reliable catch-all across dismissal routes (cf. passkey_confirm.bundle.js).
		if (d.$wrapper && d.$wrapper.on) {
			d.$wrapper.on("hide.bs.modal", function () { if (!d._acted) { d._acted = true; recordNudge(M.NUDGE_EVENTS.DECLINED); } });
		}
		d.show();
		recordNudge(M.NUDGE_EVENTS.SHOWN);
	}

	function conditionalCreate(onNotUpgraded) {
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") { onNotUpgraded(); return; }
		var upgraded = false;
		return post(METHODS.beginRegistration, { flow: "conditional_create" }).then(function (res) {
			if (!res || !res.ok) return;
			var begin = unwrap(res.body) || {};
			var options;
			try { options = parseCreate(begin.options); } catch (e) { return; }
			options.extensions = Object.assign({}, options.extensions || {}, { credProps: true });
			// An explicit ceremony may already be in flight (e.g. the user clicked
			// "Add" before the silent upgrade armed) — don't serialize behind it.
			abortConditionalCreate();
			var controller = newAbortController();
			_conditionalCreateAbort = controller;
			return navigator.credentials.create({
				publicKey: options,
				mediation: "conditional",
				signal: controller ? controller.signal : undefined,
			}).then(function (cred) {
				_conditionalCreateAbort = null;
				if (!cred) return;
				var payload = C.registrationResponseToJSON(cred);
				return post(METHODS.verifyRegistration, { state_id: begin.state_id, credential: JSON.stringify(payload) }).then(function (v) {
					if (!v || !v.ok) return;
					upgraded = true;
					fireSignal(unwrap(v.body));
				});
			});
		}).then(function () {
			if (!upgraded) onNotUpgraded();
		}, function (err) {
			_conditionalCreateAbort = null;
			if (!upgraded && (!err || err.name !== "AbortError")) onNotUpgraded();
		});
	}

	// Resolves the response, or null on a transport failure (never rejects).
	function recordNudge(event) {
		return post(METHODS.recordNudge, { event: event }).catch(function () { return null; });
	}

	// ------------------------------------------------------ enforcement gate
	function recordEnforcement(event) {
		return post(METHODS.recordEnforcement, { event: event });
	}
	var _recordSessionEvent = M.createSessionEventRecorder(getSessionStorage());
	function recordEnforcementDefer(b, enf) {
		var user = (window.frappe && frappe.session && frappe.session.user) || "current";
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
	// Report an incapable device at most once per session (avoids a second admin email
	// when the escape is clicked again).
	var _incapableReported = false;
	function reportIncapableOnce() {
		if (_incapableReported) return;
		_incapableReported = true;
		recordEnforcement(M.ENFORCE_EVENTS.INCAPABLE).catch(function () {});
	}

	// The post-login enforcement interstitial. A blocking gate is static; its only exits
	// are enrolling, the incapable escape and sign-out. "Remind me later" shows the real
	// remaining grace count.
	function showEnforceDialog(b, enf) {
		var d = new frappe.ui.Dialog({ title: t(M.COPY.enforceTitle), size: "small" });
		var body = d.$body ? d.$body.get(0) : null;
		if (body) {
			body.appendChild(el("p", "passkey-nudge-body", t(M.COPY.enforceBody)));
			var actions = el("div", "passkey-nudge-actions");
			// Runs under the fresh-login sudo window; the gate stays open until enrollment succeeds.
			actions.appendChild(primaryButton(t(M.COPY.nudgeCta), function () { enforceCreate(d); }));
			if (!enf.blocking) {
				var later = M.format(t(M.COPY.enforceRemindLater), [enf.graceRemaining]);
				actions.appendChild(linkButton(later, function () {
					d._acted = true; recordEnforcementDefer(b, enf); d.hide();
				}));
			} else {
				// Only Block + Notify Admin actually notifies an administrator; under Degrade
				// the escape just lets the user through.
				var notifiesAdmin = ((b && b.enforcement) || {}).incapable_policy === "block_notify";
				var escapeLabel = notifiesAdmin ? M.COPY.enforceContactAdmin : M.COPY.enforceCantSetUp;
				actions.appendChild(linkButton(t(escapeLabel), function () {
					onEnforceCantSetUp(b, d, body);
				}));
				actions.appendChild(linkButton(t(M.COPY.enforceSignOut), signOut));
			}
			body.appendChild(actions);
		}
		makeStaticIfBlocking(d, enf.blocking);
		// Dismissing a non-blocking gate is "Remind me later": it spends one grace login.
		// `_acted` stops a double count after the explicit link.
		if (!enf.blocking && d.$wrapper && d.$wrapper.on) {
			d.$wrapper.on("hide.bs.modal", function () {
				if (!d._acted) { d._acted = true; recordEnforcementDefer(b, enf); }
			});
		}
		d.show();
	}

	function enforceCreate(d) {
		announce(t("Follow your device's prompt to add a passkey…"));
		addPasskey({}).then(function () {
			announce(t("Passkey added."));
			d._acted = true; d.hide(); refresh({});
		}).catch(function (err) {
			// Cancel / OS-sheet dismiss ⇒ keep the (possibly blocking) gate open, no scolding.
			if (err && (err.silent || err.code === "user_cancelled")) return;
			var msg = (err && (err.userMessage || err.message)) || t(M.COPY.addFailed);
			frappe.msgprint({ title: t("Couldn't add passkey"), message: escapeHtml(msg), indicator: "orange" });
		});
	}

	// The blocking gate's escape: trust the claim, record it, then honor the site's
	// incapable-device policy — Degrade lets them proceed (prompted again next session),
	// Block + Notify Admin alerts the admin and keeps the gate up with a notice.
	function onEnforceCantSetUp(b, d, body) {
		reportIncapableOnce();
		var enf = (b && b.enforcement) || {};
		if (enf.incapable_policy === "block_notify") {
			body.innerHTML = "";
			var notice = el("p", "passkey-nudge-body", t(M.COPY.enforceBlockedNotice));
			notice.setAttribute("role", "alert");
			body.appendChild(notice);
			var actions = el("div", "passkey-nudge-actions");
			actions.appendChild(primaryButton(t(M.COPY.enforceRetry), function () { enforceCreate(d); }));
			actions.appendChild(linkButton(t(M.COPY.enforceSignOut), signOut));
			body.appendChild(actions);
		} else {
			d._acted = true;
			d.hide();
		}
	}

	// Static backdrop, no keyboard dismiss, no close-X. Best-effort across Frappe versions.
	function makeStaticIfBlocking(d, blocking) {
		if (!blocking) return;
		try {
			if (d.$wrapper && d.$wrapper.modal) {
				d.$wrapper.attr("data-backdrop", "static").attr("data-keyboard", "false");
			}
		} catch (e) { /* noop */ }
		try {
			if (d.header && d.header.find) d.header.find(".btn-modal-close, .modal-actions .close").hide();
		} catch (e) { /* noop */ }
	}

	// ------------------------------------------------------------ small utils
	function storageGet(k) { try { return window.localStorage ? localStorage.getItem(k) : null; } catch (e) { return null; } }
	function getSessionStorage() { try { return window.sessionStorage || null; } catch (e) { return null; } }
	function signOut() {
		if (window.frappe && frappe.app && typeof frappe.app.logout === "function") {
			frappe.app.logout();
			return;
		}
		window.location.href = "/api/method/logout";
	}
	function clearUpsellFlag() { try { if (window.localStorage) localStorage.removeItem(M.UPSELL_FLAG_KEY); } catch (e) { /* storage unavailable */ } }
	function announce(msg) { C.announce(document, msg); }
	function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
	function primaryButton(label, on) { var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-primary btn-sm passkey-btn"; b.textContent = label; b.addEventListener("click", on); return b; }
	function linkButton(label, on) { var b = document.createElement("button"); b.type = "button"; b.className = "btn btn-link btn-sm passkey-btn"; b.textContent = label; b.addEventListener("click", on); return b; }
	function iconButton(cls, iconName, name, on) {
		var b = document.createElement("button");
		b.type = "button";
		b.className = "btn btn-xs btn-default passkey-icon-btn " + cls;
		b.setAttribute("aria-label", name); // accessible name for icon-only action
		b.setAttribute("title", name);
		var g = el("span", "passkey-icon"); g.setAttribute("aria-hidden", "true");
		g.innerHTML = C.iconSvg(iconName, "icon icon-sm");
		b.appendChild(g);
		b.addEventListener("click", on);
		return b;
	}
	function fmtDate(v) {
		if (!v) return "—";
		try { if (window.frappe && frappe.datetime && frappe.datetime.str_to_user) return frappe.datetime.str_to_user(v); } catch (e) { /* fall back to the raw value */ }
		return String(v);
	}
	function escapeHtml(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

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
	window.frappe = window.frappe || {};
	window.frappe.passkeys = window.frappe.passkeys || {};
	window.frappe.passkeys.manage = manage;
	window.frappe.ui = window.frappe.ui || {};
	window.frappe.ui.passkey = window.frappe.ui.passkey || {};
	if (!window.frappe.ui.passkey.manage) window.frappe.ui.passkey.manage = manage;

	// ------------------------------------------------------------- desk boot
	// Frappe's route change (container.js change_to) hides `cur_dialog`, and after_ajax can
	// fire before the landing page renders; a nudge opened then is torn down and records a
	// decline the user never made. So wait for the first page render.
	function nudgeAfterInitialRender() {
		if (window.frappe && frappe.container && frappe.container.page) {
			maybeNudge();
		} else if (window.jQuery) {
			jQuery(document).one("page-change", function () { maybeNudge(); });
		} else {
			maybeNudge();
		}
	}

	function onReady() {
		var b = boot();
		// Management surfaces gate on ANY passkey mode: both modes off
		// (or a dormant/uninstalled app ⇒ no bootinfo) ⇒ the UI removes itself.
		if (!b || b.enabled === false) return;
		nudgeAfterInitialRender();
		refreshSignalsInSession();
	}
	if (window.frappe && frappe.router && frappe.after_ajax) frappe.after_ajax(onReady);
	else if (document.readyState !== "loading") setTimeout(onReady, 0);
	else document.addEventListener("DOMContentLoaded", function () { setTimeout(onReady, 0); });

	// Node-only test seam; `module` is undefined in the browser.
	if (typeof module === "object" && module.exports) {
		module.exports = { showEnforceDialog: showEnforceDialog, showNudgeDialog: showNudgeDialog, maybeNudge: maybeNudge, recordNudge: recordNudge };
	}
})();
