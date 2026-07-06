// passkey_settings.js — the Passkey Settings form UX (DESIGN-v1 §9.4). Wired via
// `doctype_js = {"Passkey Settings": "public/js/passkey_settings.js"}` (see the
// build manifest). Renders the §9.4 banner/dialog matrix on the settings form and
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
		paintBanners(frm, M);
	},
	// Repaint on any knob change so the matrix stays live before save.
	login_with_passkey: repaint,
	passkey_as_second_factor: repaint,
	passkey_notify_on_change: repaint,
	passkey_origins: repaint,
	passkey_rp_id: function (frm) {
		repaint(frm);
		// One-way door (§9.1/§9.2): changing the RP ID after enrollment invalidates
		// every passkey. Loud typed confirm before the value can be saved.
		if (frm.doc.__islocal || !frm.doc.passkey_rp_id) return;
		if (frm._passkey_rpid_ack === frm.doc.passkey_rp_id) return;
		frappe.warn(
			__("Change the RP ID?"),
			__(M.COPY.rpIdOneWayDoor),
			function () { frm._passkey_rpid_ack = frm.doc.passkey_rp_id; },
			__("Yes, change it"),
			true // set_danger
		);
	},
});

function repaint(frm) {
	var M = frappe.passkeys_manage_common;
	if (M) paintBanners(frm, M);
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
	// Resolved RP ID / origins read-only echo (§9.1 "Read-only display").
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
// rp_id ⇒ the current host, §9.2 exact-host default). Cross-flag data rides
// frappe.boot.passkeys.settings_context when the server ships it (optional — the
// pure matrix omits the banners that need it if absent).
function buildContext(frm) {
	var boot = (frappe.boot && frappe.boot.passkeys) || {};
	var sc = boot.settings_context || {};
	var host = window.location && window.location.hostname;
	var rpId = (frm.doc.passkey_rp_id || "").trim() || host;
	var origins = parseOrigins(frm.doc.passkey_origins, rpId);
	return {
		currentHost: host,
		resolvedRpId: rpId,
		resolvedOrigins: origins,
		// server-supplied cross-flag context (optional)
		coreTwoFactor: sc.core_two_factor_auth,
		disablePassLogin: sc.disable_user_pass_login,
		passkeyOnlyUserCount: sc.passkey_only_user_count,
	};
}

function parseOrigins(raw, rpId) {
	var lines = String(raw || "").split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
	if (!lines.length && rpId) return ["https://" + rpId];
	return lines;
}
