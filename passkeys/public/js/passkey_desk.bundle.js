// passkey_desk.bundle.js — Desk-wide credential management + enrollment nudges.
// Loaded via app_include_js on every Desk page, AFTER
// passkey_common.js (frappe.passkeys_common), passkey_manage_common.js
// (frappe.passkeys_manage_common) and passkey_confirm.js (frappe.passkeys.confirm/
// call). Destination on core merge: frappe/public/js/frappe/passkey/desk.js.
//
// Publishes `frappe.passkeys.manage`:
//   renderCards(container, opts)        — the shared card component (own creds)
//   renderReadOnlyInventory(el, user)   — System-Manager view of another user
//   openManagerDialog()                 — the "My Passkeys" manager dialog (kept for
//                                         CTAs/nudges; the primary home is the User
//                                         form "Passkeys" section, user_passkeys.js)
//   addPasskey(opts)                    — the registration ceremony (sudo-gated)
//   refresh()                           — re-fetch + repaint any live surface
//
// It also, at Desk boot: runs the post-login enrollment nudge / conditional-create /
// post-hybrid upsell off frappe.boot.passkeys, and fires
// signalAllAcceptedCredentials fire-and-forget.
//
// The DOM/frappe wiring lives here; all pure decisions (view-models, nudge
// cadence, upsell gate, delete guard) come from passkey_manage_common.js so they
// stay node-testable without a bench.
//
// eslint-env browser
(function () {
	"use strict";

	var C = window.frappe && window.frappe.passkeys_common;
	var M = window.frappe && window.frappe.passkeys_manage_common;
	if (!C || !M) return; // shared libs missing — fail safe, never throw on Desk boot

	var t = C.t;
	var METHODS = M.MANAGE_METHODS;

	// A pending conditionalCreate() (mediation:"conditional") holds a WebAuthn
	// request open for the whole tab; the platform serializes credential requests,
	// so any later EXPLICIT ceremony (registration or a confirm gesture) throws
	// "A request is already pending" until it's aborted. Mirror the login bundle's
	// AbortController discipline: store the controller, pass its signal into
	// create(), and abort it before any explicit ceremony in this tab.
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
	// Client provider snapshot. Optional release asset; absent ⇒ {} ⇒ cards
	// fall back to the server-supplied `provider` field or "Unknown provider".
	var _aaguidMap = null;
	function loadAaguidMap() {
		if (_aaguidMap) return Promise.resolve(_aaguidMap);
		return fetch("/assets/passkeys/aaguid-map.json", { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : {}; })
			.catch(function () { return {}; })
			.then(function (map) { _aaguidMap = map || {}; return _aaguidMap; });
	}

	// ---------------------------------------------------------------- transport
	// Raw fetch so we own the 401 body (the retry contract for sudo-gated
	// mutations). Resolves {ok, status, body} for ANY status; rejects only on a
	// transport failure. Mirrors passkey_confirm.js::post.
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
		if (extra) for (var k in extra) if (extra.hasOwnProperty(k)) h[k] = extra[k];
		return h;
	}
	function unwrap(body) { return C.unwrapMessage(body); }

	// -------------------------------------------------------------- sudo dance
	// A sudo-gated mutation: call the method; on the 401 contract run a
	// passkeys.manage confirmation (passkey-first, password fallback — the confirm
	// client owns that dialog + a11y), then retry once with the grant header. The
	// confirmation re-seeds the full-sudo window so the retry passes.
	function guardedCall(method, args) {
		// The confirm engine runs a WebAuthn get() gesture; abort any pending
		// conditionalCreate() first so it doesn't serialize behind it.
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

	// Ensure a live management sudo window before a multi-step ceremony
	// (registration is begin→create→verify, so it can't ride guardedCall's single
	// retry). Returns a promise that resolves once the window is seeded.
	function ensureManageSudo() {
		// Same as guardedCall: the confirm gesture is an explicit ceremony.
		abortConditionalCreate();
		if (window.frappe && window.frappe.passkeys && window.frappe.passkeys.confirm) {
			return window.frappe.passkeys.confirm(M.MANAGE_ACTION);
		}
		return Promise.reject(new Error("confirmation_unavailable"));
	}

	// ---------------------------------------------------------- registration
	// Add a passkey (explicit flow). Sudo-gated: try begin; on the 401
	// contract run a management confirmation then retry begin. On success run the
	// modal create() (with the credProps extension) and verify.
	function addPasskey(opts) {
		opts = opts || {};
		// Serialize-safety: an explicit registration must not race a pending
		// conditionalCreate() get/create held open in this tab.
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
				var payload = cred.toJSON ? cred.toJSON() : C.authAssertionToJSON(cred);
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
		var payload = M.signalPayload(data);
		if (payload && window.PublicKeyCredential && typeof PublicKeyCredential.signalAllAcceptedCredentials === "function") {
			try {
				var p = PublicKeyCredential.signalAllAcceptedCredentials({
					rpId: rpId,
					userId: payload.userHandle,
					// F3: an EMPTY allAcceptedCredentialIds is intentional after a genuine
					// last-passkey delete — the provider then hides ALL of this user's passkeys.
					// It only reaches here behind res.ok, never on a failed list read.
					allAcceptedCredentialIds: payload.allAcceptedCredentialIds,
				});
				if (p && p.catch) p.catch(function () {}); // Safari 26 never-settles / Firefox absent
			} catch (e) { /* fire-and-forget */ }
		}
		// F2: keep the provider's stored username/display name in sync with the RP so the
		// account chooser doesn't drift after a full_name/email edit.
		var details = M.currentUserDetailsPayload(data);
		if (details && window.PublicKeyCredential && typeof PublicKeyCredential.signalCurrentUserDetails === "function") {
			try {
				var q = PublicKeyCredential.signalCurrentUserDetails({
					rpId: rpId,
					userId: details.userHandle,
					name: details.name,
					displayName: details.displayName,
				});
				if (q && q.catch) q.catch(function () {}); // Safari 26 never-settles / Firefox absent
			} catch (e) { /* fire-and-forget */ }
		}
	}
	function refreshSignalsInSession() {
		post(METHODS.getSignalData, {}).then(function (res) {
			if (res && res.ok) fireSignal(unwrap(res.body));
		}).catch(function () {});
	}

	// ============================================================ card component
	// The shared card component. Renders the caller's own credentials into
	// `container`; wires rename (inline, no sudo) + delete (confirm + sudo gate) +
	// the empty-state "Create a passkey" hero + the add button. a11y.
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
				list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map }), opts));
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

	// passwordless-login switch. Current value rides the list payload
	// (server-authoritative), with the boot flag as a fallback; defaults OFF when
	// neither ships it yet. Disabled when the user has no usable (enabled) passkey —
	// you can't go passwordless with none, and enabling needs a passkey grant anyway.
	function isPasskeyOnly(payload) {
		if (payload && payload.passkey_only_login !== undefined) return !!payload.passkey_only_login;
		var b = boot();
		return !!(b && b.passkey_only_login);
	}

	function passkeyOnlyRow(creds, payload, opts) {
		var enabledCount = 0;
		creds.forEach(function (c) { if (M.credentialViewModel(c).enabled) enabledCount += 1; });
		var current = isPasskeyOnly(payload);

		var row = el("div", "passkey-only-row");
		var main = el("div", "passkey-only-main");
		main.appendChild(el("div", "passkey-only-label", t(M.COPY.passkeyOnlyLabel)));
		main.appendChild(el("div", "passkey-only-help", t(M.COPY.passkeyOnlyHelp)));
		row.appendChild(main);

		var toggle = document.createElement("input");
		toggle.type = "checkbox";
		toggle.className = "passkey-only-toggle";
		toggle.checked = current;
		toggle.setAttribute("role", "switch");
		toggle.setAttribute("aria-checked", current ? "true" : "false");
		toggle.setAttribute("aria-label", t(M.COPY.passkeyOnlyLabel));
		if (enabledCount === 0) {
			toggle.disabled = true;
			toggle.setAttribute("title", t(M.COPY.passkeyOnlyHelp));
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

	// Sudo-gated toggle: confirm + a single-use PASSKEY grant only —
	// mirrors deleteCard's sudo dance. guardedCall runs the 401 confirm and
	// retries with the grant; the boolean {enabled} payload matches the fingerprint
	// the server binds the grant to ({"enabled": <bool>}).
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

	// System-Manager read-only inventory of ANOTHER user. list_* only
	// ever returns the SESSION user's rows, so we read the DocType directly (System
	// Manager has read); disable/delete happen on the WebAuthn Credential DocType.
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
				list.appendChild(cardEl(M.credentialViewModel(cred, { aaguidMap: map }), { readOnly: true }));
			});
			container.appendChild(list);
			var link = document.createElement("a");
			link.className = "passkey-admin-link";
			link.href = "/app/webauthn-credential?user=" + encodeURIComponent(user);
			link.textContent = t("Manage in the WebAuthn Credential list");
			container.appendChild(link);
		});
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
			// Re-render UNCONDITIONALLY with the known root so every reopen fetches fresh
			// via list_credentials. The old refresh({dialog}) path passed no `.root` and
			// then gated on $wrapper.is(":visible") — which is false mid fade-in — so the
			// re-render was skipped and the stale DOM from the first open showed (A3).
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

	// Native dialog affordance to re-fetch the card list on demand (e.g. a passkey was
	// added or removed on another device while this dialog stayed open). Uses
	// frappe.ui.Dialog.add_custom_action (present on v15/v16/develop); a no-op if it's
	// somehow unavailable, so the dialog still opens.
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

	function maybeNudge() {
		var b = boot();
		if (!b) return; // no bootinfo contract yet ⇒ safe no-op (server dependency)
		Promise.all([C.detectCapabilities({ window: window }), probeConditionalCreate()]).then(function (r) {
			var caps = r[0];
			var clientCaps = {
				supported: caps.supported,
				uvpaa: caps.uvpaa,
				conditionalCreate: r[1] === true, // certain-true only
			};
			// post-hybrid upsell takes precedence (the login just happened over hybrid)
			var upsell = M.upsellDecision(b, clientCaps, storageGet, Date.now());
			if (upsell.showUpsell) { clearUpsellFlag(); return showNudgeDialog(b, true); }
			// silent conditional create (no dialog) — Firefox has none, so the visible
			// nudge is its whole story
			var d = M.nudgeDecision(b, clientCaps, Date.now());
			if (d.allowConditionalCreate) { conditionalCreate(); return; }
			if (d.showNudge) showNudgeDialog(b, false);
		}).catch(function () {});
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
		recordNudge(M.NUDGE_EVENTS.SHOWN);
		var titleKey = isUpsell ? M.COPY.upsellTitle : M.COPY.nudgeTitle;
		var bodyKey = isUpsell ? M.COPY.upsellBody : M.COPY.nudgeBody;
		var d = new frappe.ui.Dialog({ title: t(titleKey), size: "small" });
		var act = function (event) { if (d._acted) return; d._acted = true; if (event) recordNudge(event); d.hide(); };
		var body = d.$body ? d.$body.get(0) : null;
		if (body) {
			body.appendChild(el("p", "passkey-nudge-body", t(bodyKey)));
			var actions = el("div", "passkey-nudge-actions");
			actions.appendChild(primaryButton(t(M.COPY.nudgeCta), function () {
				// CTA runs under the fresh-login sudo window — zero re-prompt.
				d._acted = true; d.hide(); triggerAdd({});
			}));
			actions.appendChild(linkButton(t(M.COPY.nudgeLater), function () { act(M.NUDGE_EVENTS.DECLINED); }));
			actions.appendChild(linkButton(t(M.COPY.nudgeNever), function () { act(M.NUDGE_EVENTS.OPT_OUT); }));
			body.appendChild(actions);
		}
		// Esc / backdrop dismiss = "Not now" semantics: the modal's hide event
		// is the one reliable catch-all across dismissal routes (cf. passkey_confirm.js).
		if (d.$wrapper && d.$wrapper.on) {
			d.$wrapper.on("hide.bs.modal", function () { if (!d._acted) { d._acted = true; recordNudge(M.NUDGE_EVENTS.DECLINED); } });
		}
		d.show();
	}

	function conditionalCreate() {
		if (!navigator.credentials || typeof navigator.credentials.create !== "function") return;
		post(METHODS.beginRegistration, { flow: "conditional_create" }).then(function (res) {
			if (!res || !res.ok) return; // silent no-op
			var begin = unwrap(res.body) || {};
			var options;
			try { options = parseCreate(begin.options); } catch (e) { return; }
			options.extensions = Object.assign({}, options.extensions || {}, { credProps: true });
			// An explicit ceremony may already be in flight (e.g. the user clicked
			// "Add" before the silent upgrade armed) — don't serialize behind it.
			abortConditionalCreate();
			var controller = newAbortController();
			_conditionalCreateAbort = controller;
			navigator.credentials.create({
				publicKey: options,
				mediation: "conditional",
				signal: controller ? controller.signal : undefined,
			}).then(function (cred) {
				_conditionalCreateAbort = null;
				if (!cred) return;
				var payload = cred.toJSON ? cred.toJSON() : C.authAssertionToJSON(cred);
				post(METHODS.verifyRegistration, { state_id: begin.state_id, credential: JSON.stringify(payload) }).then(function (v) {
					if (v && v.ok) fireSignal(unwrap(v.body));
				});
			}).catch(function () { _conditionalCreateAbort = null; /* silent on decline/absence/abort */ });
		}).catch(function () {});
	}

	function recordNudge(event) {
		post(METHODS.recordNudge, { event: event }).catch(function () {}); // server counters authoritative
	}

	// ------------------------------------------------------------ small utils
	function storageGet(k) { try { return window.localStorage ? localStorage.getItem(k) : null; } catch (e) { return null; } }
	function clearUpsellFlag() { try { if (window.localStorage) localStorage.removeItem(M.UPSELL_FLAG_KEY); } catch (e) {} }
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
		try { if (window.frappe && frappe.datetime && frappe.datetime.str_to_user) return frappe.datetime.str_to_user(v); } catch (e) {}
		return String(v);
	}
	function escapeHtml(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

	// ------------------------------------------------------------------ publish
	var manage = {
		renderCards: renderCards,
		renderReadOnlyInventory: renderReadOnlyInventory,
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
	function onReady() {
		var b = boot();
		// Management surfaces gate on ANY passkey mode: both modes off
		// (or a dormant/uninstalled app ⇒ no bootinfo) ⇒ the UI removes itself.
		if (!b || b.enabled === false) return;
		maybeNudge();
		refreshSignalsInSession();
	}
	if (window.frappe && frappe.router && frappe.after_ajax) frappe.after_ajax(onReady);
	else if (document.readyState !== "loading") setTimeout(onReady, 0);
	else document.addEventListener("DOMContentLoaded", function () { setTimeout(onReady, 0); });
})();
