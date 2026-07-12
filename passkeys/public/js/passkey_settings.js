// passkey_settings.js — the Passkey Settings form UX. Wired via
// `doctype_js = {"Passkey Settings": "public/js/passkey_settings.js"}` (see the
// build manifest). Renders the banner/dialog matrix on the settings form and
// puts the loud one-way-door confirm on the RP-ID field. Destination on core merge:
// the passkey section of frappe/core/doctype/system_settings/system_settings.js.
//
// The banner DECISIONS come from passkey_manage_common.js::settingsBanners (pure,
// node-tested); this file only paints them and wires the confirm dialog. Cross-flag
// context (core enable_two_factor_auth / disable_user_pass_login / the passkey-only
// user count) is read from frappe.boot.passkeys.settings_context when the server
// provides it — see the manifest for the exact contract.
//
// eslint-env browser
frappe.ui.form.on("Passkey Settings", {
	refresh: function (frm) {
		var M = frappe.passkeys_manage_common;
		if (!M) return;
		// Baseline for the RP-ID one-way-door revert: the last-saved value to
		// fall back to if the user backs out of the confirm. refresh() re-fires after
		// every load and save, so this always tracks the persisted RP ID.
		frm._passkey_rpid_saved = frm.doc.passkey_rp_id;
		paintBanners(frm, M);
		// Pull the RP ID the SERVER will actually resolve right now (fresh — boot can
		// be stale on a settings page left open, e.g. after host_name was just set in
		// site_config.json). Repaints once it lands so the banner matches Save exactly.
		fetchResolvedRpId(frm);
		// The security-posture verdict — "what should I see first": can a passkey be
		// bypassed right now, and how to close each gap. Reads SAVED server state, so it
		// is fetched on refresh (which also fires after every save), not on keystroke.
		fetchSecurityPosture(frm, M);
	},
	// Repaint on any knob change so the matrix stays live before save.
	login_with_passkey: repaint,
	passkey_as_second_factor: repaint,
	passkey_notify_on_change: repaint,
	passkey_origins: repaint,
	// enrollment ladder + enforcement scope/escape-hatch knobs
	passkey_enrollment_policy: repaint,
	passkey_enforce_after: repaint,
	passkey_enforce_scope: repaint,
	passkey_enforce_roles: repaint,
	passkey_enforce_exempt_roles: repaint,
	passkey_enforce_incapable: repaint,
	passkey_rp_id: function (frm) {
		repaint(frm);
		var M = frappe.passkeys_manage_common;
		if (!M) return;
		// One-way door: changing the RP ID after enrollment invalidates
		// every passkey. Loud typed confirm before the value can be saved.
		if (frm.doc.__islocal || !frm.doc.passkey_rp_id) return;
		if (frm._passkey_rpid_ack === frm.doc.passkey_rp_id) return;
		var saved = (frm.doc_before_save && frm.doc_before_save.passkey_rp_id) ||
			frm._passkey_rpid_saved || "";
		var proceeded = false;
		var d = frappe.warn(
			__("Change the RP ID?"),
			__(M.COPY.rpIdOneWayDoor),
			function () { proceeded = true; frm._passkey_rpid_ack = frm.doc.passkey_rp_id; },
			__("Yes, change it"),
			true // set_danger — Cancel is the safe default
		);
		// Cancel / Esc / backdrop dismissal MUST revert the field, so a backed-out
		// change can never be saved (the confirm has to actually gate the save).
		// The modal hide event is the reliable catch-all across dismissal routes
		// (same idiom as the desk nudge dialog + passkey_confirm.js::wireCancel).
		if (d && d.$wrapper && d.$wrapper.on) {
			d.$wrapper.on("hide.bs.modal", function () {
				if (proceeded) return;
				// Ack the reverted value first so set_value's change event short-circuits
				// (no re-opening the warn).
				frm._passkey_rpid_ack = saved;
				frm.set_value("passkey_rp_id", saved);
			});
		}
	},
});

function repaint(frm) {
	var M = frappe.passkeys_manage_common;
	if (M) paintBanners(frm, M);
}

// Fetch the RP ID the server resolves right now (System-Manager-gated, read-only
// endpoint). Cached on the form and read by buildContext; on failure we fall back to
// frappe.boot.passkeys.rp_id, so the display is never worse than boot.
function fetchResolvedRpId(frm) {
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_resolved_rp_id",
		callback: function (r) {
			if (!r || !r.message) return;
			frm._passkey_server_rpid = r.message.rp_id || null;
			frm._passkey_host_name_configured = !!r.message.host_name_configured;
			repaint(frm);
		},
	});
}

// Fetch + paint the admin security-posture verdict (System-Manager-gated, read-only
// endpoint). The panel is a PURE renderer (M.posturePanel) fed by the server rows; this
// only paints the returned view-model. On failure the panel simply doesn't render (no
// worse than before it existed).
function fetchSecurityPosture(frm, M) {
	if (!M.posturePanel) return;
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_security_posture",
		callback: function (r) {
			if (!r || !r.message) return;
			paintPosture(frm, M, r.message);
		},
	});
}

function paintPosture(frm, M, response) {
	var host = postureHost(frm);
	if (!host) return;
	while (host.firstChild) host.removeChild(host.firstChild); // idempotent across repaints

	var panel = M.posturePanel(response);

	var title = document.createElement("div");
	title.className = "passkey-posture-title";
	title.textContent = __("Security posture");
	host.appendChild(title);

	// The one verdict line first — the attention anchor.
	var verdictClass = panel.headline.tone === "high" ? "danger"
		: panel.headline.tone === "good" ? "success" : "info";
	var verdict = document.createElement("div");
	verdict.className = "passkey-posture-verdict alert alert-" + verdictClass;
	verdict.setAttribute("role", panel.headline.canBypass ? "alert" : "status");
	verdict.textContent = panel.headline.text;
	host.appendChild(verdict);

	// Severity-ordered rows: one problem line + one recommendation line each.
	panel.rows.forEach(function (row) {
		host.appendChild(postureRowEl(row));
	});
}

function postureRowEl(row) {
	var color = row.severity === "high" ? "red"
		: row.severity === "medium" ? "orange"
		: row.severity === "low" ? "blue" : "gray";
	var wrap = document.createElement("div");
	wrap.className = "passkey-posture-row";
	wrap.setAttribute("data-indicator", color);
	if (!row.detectable) wrap.classList.add("passkey-posture-note");

	var problem = document.createElement("div");
	problem.className = "passkey-posture-problem";
	var what = document.createElement("strong");
	what.textContent = row.what;
	problem.appendChild(what);
	if (row.why) {
		var why = document.createElement("span");
		why.className = "passkey-posture-why text-muted";
		why.textContent = " " + row.why;
		problem.appendChild(why);
	}
	wrap.appendChild(problem);

	if (row.recommendation) {
		var fix = document.createElement("div");
		fix.className = "passkey-posture-fix";
		fix.textContent = row.recommendation;
		wrap.appendChild(fix);
	}
	return wrap;
}

// A self-managed posture container, mounted ABOVE the banner host so the verdict is the
// first thing an admin sees. Cleared on every paint (never stacks duplicates).
function postureHost(frm) {
	if (frm._passkey_posture_host && frm._passkey_posture_host.isConnected) return frm._passkey_posture_host;
	var $mount = (frm.layout && frm.layout.wrapper) || (frm.dashboard && frm.dashboard.wrapper) || frm.$wrapper;
	var mount = $mount && $mount.get ? $mount.get(0) : $mount;
	if (!mount) return null;
	var host = document.createElement("div");
	host.className = "passkey-posture";
	// Insert above the banner host when it exists, else at the very top of the form.
	var before = (frm._passkey_banner_host && frm._passkey_banner_host.isConnected)
		? frm._passkey_banner_host : mount.firstChild;
	mount.insertBefore(host, before);
	frm._passkey_posture_host = host;
	return host;
}

function paintBanners(frm, M) {
	var host = bannerHost(frm);
	if (!host) return;
	while (host.firstChild) host.removeChild(host.firstChild); // idempotent across repaints

	var ctx = buildContext(frm);
	var banners = M.settingsBanners(frm.doc, ctx);
	// Render errors first, then warnings, then info.
	var order = { error: 0, warning: 1, info: 2 };
	banners.sort(function (a, b) { return (order[a.level] || 9) - (order[b.level] || 9); });
	banners.forEach(function (bn) {
		host.appendChild(bannerEl(bn.level, M.format(__(bn.key), bn.args || [])));
	});
	// Resolved RP ID / origins read-only echo ("Read-only display").
	if (ctx.resolvedRpId || (ctx.resolvedOrigins && ctx.resolvedOrigins.length)) {
		var lines = [];
		if (ctx.resolvedRpId) lines.push(__("Resolved RP ID: {0}", [ctx.resolvedRpId]));
		if (ctx.resolvedOrigins && ctx.resolvedOrigins.length) lines.push(__("Origins: {0}", [ctx.resolvedOrigins.join(", ")]));
		host.appendChild(bannerEl("info", lines.join(" · ")));
	}
}

// A self-managed banner container so repaints never stack duplicates. Mounted once
// at the top of the form layout; cleared on every paint.
function bannerHost(frm) {
	if (frm._passkey_banner_host && frm._passkey_banner_host.isConnected) return frm._passkey_banner_host;
	var $mount = (frm.layout && frm.layout.wrapper) || (frm.dashboard && frm.dashboard.wrapper) || frm.$wrapper;
	var mount = $mount && $mount.get ? $mount.get(0) : $mount;
	if (!mount) return null;
	var host = document.createElement("div");
	host.className = "passkey-settings-banners";
	mount.insertBefore(host, mount.firstChild);
	frm._passkey_banner_host = host;
	return host;
}

function bannerEl(level, msg) {
	var color = level === "error" ? "red" : level === "warning" ? "orange" : "blue";
	var div = document.createElement("div");
	div.className = "passkey-settings-banner alert alert-" + (level === "error" ? "danger" : level === "warning" ? "warning" : "info");
	div.setAttribute("role", level === "info" ? "status" : "alert");
	div.setAttribute("data-indicator", color);
	div.textContent = msg; // plain text — never innerHTML (msg is translated copy + values)
	return div;
}

// Resolve the settings context. RP ID / origins are computed from the doc (blank
// rp_id ⇒ the current host, exact-host default). Cross-flag data rides
// frappe.boot.passkeys.settings_context when the server ships it (optional — the
// pure matrix omits the banners that need it if absent).
function buildContext(frm) {
	var boot = (frappe.boot && frappe.boot.passkeys) || {};
	var sc = boot.settings_context || {};
	var host = window.location && window.location.hostname;
	// Server-truth resolution, mirroring policy.resolve_rp_id: an explicit RP ID wins
	// (the server validates + lowercases it); otherwise the value the SERVER resolves
	// from host_name — fetched live (frm._passkey_server_rpid), falling back to the
	// boot value before that lands. NEVER window.location.hostname: the browser host is
	// not what the server uses, so showing it makes the form disagree with Save (A1).
	var explicit = (frm.doc.passkey_rp_id || "").trim().toLowerCase();
	var serverResolved = frm._passkey_server_rpid !== undefined
		? frm._passkey_server_rpid
		: (boot.rp_id || null);
	var rpId = explicit || serverResolved || null;
	var origins = parseOrigins(frm.doc.passkey_origins, rpId);
	return {
		currentHost: host,
		resolvedRpId: rpId,
		resolvedOrigins: origins,
		hostNameConfigured: frm._passkey_host_name_configured,
		// server-supplied cross-flag context (optional)
		coreTwoFactor: sc.core_two_factor_auth,
		disablePassLogin: sc.disable_user_pass_login,
		passkeyOnlyUserCount: sc.passkey_only_user_count,
		// report-only enforcement preview: in-scope users with no passkey yet
		// (server-supplied — the matrix omits the preview banner when absent).
		wouldBeBlockedCount: sc.would_be_blocked_count,
	};
}

// Derive the resolved origins the same way the server does (policy.resolve_origins):
// the implicit https://<rp_id> origin is ALWAYS included, then the custom lines.
// Delegates to the pure, node-tested helper so this stays a thin DOM glue file.
function parseOrigins(raw, rpId) {
	var M = typeof frappe !== "undefined" && frappe.passkeys_manage_common;
	if (M && M.deriveOrigins) return M.deriveOrigins(raw, rpId);
	// Fallback if the pure lib is missing — still include the implicit origin so a
	// healthy site never shows a false host-mismatch (mirror the server).
	var lines = String(raw || "").split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
	if (rpId && lines.indexOf("https://" + rpId) === -1) lines.unshift("https://" + rpId);
	return lines;
}
