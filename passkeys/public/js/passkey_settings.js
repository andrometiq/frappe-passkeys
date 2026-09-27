// The Passkey Settings form: the banners from passkey_manage_common's settingsBanners,
// the security-posture report and the RP-ID one-way-door confirm.
// eslint-env browser
frappe.ui.form.on("Passkey Settings", {
	refresh: function (frm) {
		// The last-saved RP ID, for reverting a backed-out change (refresh re-fires on save).
		frm._passkey_rpid_saved = frm.doc.passkey_rp_id;
		frm.set_df_property("passkey_app_origins", "description", __(
			"Native Android app origins may be listed here as android:apk-key-hash:<hash>. iOS needs no Trusted App Origin entry here; configure the exact HTTPS origin asserted by the iOS app under Passkey Origins. RP ID is credential scope, not an origin."
		));
		paintBanners(frm);
		fetchResolvedRpId(frm); // boot can be stale; repaints when it lands
		fetchSecurityPosture(frm); // the verdict reads SAVED state
	},
	// Repaint on any knob change so the banners stay live before save.
	login_with_passkey: paintBanners,
	passkey_as_second_factor: paintBanners,
	passkey_notify_on_change: paintBanners,
	passkey_origins: paintBanners,
	passkey_everyone_else: paintBanners,
	passkey_enforce_after: paintBanners,
	passkey_enforce_scope: paintBanners,
	passkey_enforce_roles: paintBanners,
	passkey_enforce_privileged_always: paintBanners,
	passkey_enforce_incapable: paintBanners,
	validate: function (frm) {
		var result = frappe.passkeys_manage_common.validateAndroidFingerprints(frm.doc.passkey_android_cert_fingerprints);
		if (!result.valid) {
			frappe.throw(__(
				"Each Android signing-certificate fingerprint must contain exactly 64 hexadecimal characters; colons and a SHA-256 label are optional. Invalid line(s): {0}",
				[result.invalid.join(", ")]
			));
		}
	},
	passkey_rp_id: function (frm) {
		paintBanners(frm);
		// One-way door: a new RP ID invalidates every passkey, so confirm before it can be saved.
		if (frm.doc.__islocal || !frm.doc.passkey_rp_id) return;
		if (frm._passkey_rpid_ack === frm.doc.passkey_rp_id) return;
		var saved = (frm.doc_before_save && frm.doc_before_save.passkey_rp_id) || frm._passkey_rpid_saved || "";
		var proceeded = false;
		var d = frappe.warn(
			__("Change the RP ID?"),
			__(frappe.passkeys_manage_common.COPY.rpIdOneWayDoor),
			function () { proceeded = true; frm._passkey_rpid_ack = frm.doc.passkey_rp_id; },
			__("Yes, change it"),
			true // set_danger: Cancel is the safe default
		);
		// Any dismissal reverts the field so a backed-out change can never be saved.
		d.$wrapper.on("hide.bs.modal", function () {
			if (proceeded) return;
			// Ack the reverted value first so set_value's change event doesn't reopen the warn.
			frm._passkey_rpid_ack = saved;
			frm.set_value("passkey_rp_id", saved);
		});
	},
});

function fetchResolvedRpId(frm) {
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_resolved_rp_id",
		callback: function (r) {
			if (!r || !r.message) return;
			frm._passkey_server_rpid = r.message.rp_id || null;
			frm._passkey_server_site_origin = r.message.configured_site_origin || null;
			paintBanners(frm);
		},
	});
}

// The hosted explainer the report footer links to (new tab, never iframed).
var POSTURE_THEORY_URL = "https://andrometiq.github.io/frappe-passkeys/why-passkeys.html";

function fetchSecurityPosture(frm) {
	renderPosture(frm, postureNoticeCard(__("Checking your security posture…")));
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_security_posture",
		callback: function (r) {
			if (!r || !r.message) return renderPostureFailure(frm);
			renderPosture(frm, postureNodes(frappe.passkeys_manage_common.postureReport(r.message)));
		},
		error: function () { renderPostureFailure(frm); },
	});
}

function renderPostureFailure(frm) {
	renderPosture(frm, postureNoticeCard(__("The security report couldn’t be loaded right now.")));
}

function renderPosture(frm, nodes) {
	var host = settingsFormHost(frm, "_passkey_posture_host", "passkey-posture");
	fillHost(host, [].concat(nodes));
}

// A single-line card (loading / unavailable) in the verdict card's shell, so nothing jumps.
function postureNoticeCard(text) {
	var card = postureCard("gray", "note", text);
	card.classList.add("passkey-posture-card--muted");
	return card;
}

// The verdict card and its collapsible report. No red: a bypass path is a recommendation;
// red is kept for the save-blocking banners above this card.
function postureNodes(report) {
	var tone = report.headline.tone; // "good" | "high" | "info"
	var indicator = tone === "good" ? "green" : tone === "high" ? "blue" : "gray";
	var card = postureCard(indicator, tone === "good" ? "good" : "note", report.headline.text || __("Security posture"));
	card.classList.add("passkey-posture-card--" + tone);

	var region = postureRegion(report);
	region.hidden = true;
	var ctaOpen = report.headline.canBypass ? __("View recommendations") : __("View report");
	var cta = document.createElement("button");
	cta.type = "button";
	cta.className = "btn btn-sm passkey-posture-cta btn-default";
	cta.setAttribute("aria-expanded", "false");
	cta.setAttribute("aria-controls", region.id);
	cta.textContent = ctaOpen;
	cta.addEventListener("click", function () {
		var open = region.hidden;
		region.hidden = !open;
		cta.setAttribute("aria-expanded", open ? "true" : "false");
		cta.textContent = open ? __("Hide report") : ctaOpen;
	});
	card.appendChild(cta);
	return [card, region];
}

// The card shell: the indicator rail, the mark, a "Security posture" eyebrow and the verdict
// line, announced politely (role=status).
function postureCard(indicator, markKind, verdictText) {
	var card = settingsElement("div", "passkey-posture-card");
	card.setAttribute("data-indicator", indicator);
	card.appendChild(postureMark(markKind));
	var body = settingsElement("div", "passkey-posture-headline");
	body.appendChild(settingsElement("div", "passkey-posture-eyebrow", __("Security posture")));
	var verdict = settingsElement("div", "passkey-posture-verdict-text", verdictText);
	verdict.setAttribute("role", "status");
	body.appendChild(verdict);
	card.appendChild(body);
	return card;
}

function postureRegion(report) {
	var region = settingsElement("div", "passkey-posture-report");
	region.id = "passkey-posture-report";
	region.appendChild(settingsElement("div", "passkey-posture-report-heading", __("What this checks")));
	report.rows.forEach(function (row) { region.appendChild(postureRow(row)); });
	var footer = settingsElement("div", "passkey-posture-footer");
	var link = settingsElement("a", "passkey-posture-theory", __("Why passkeys are safer — and when they aren’t →"));
	link.href = POSTURE_THEORY_URL;
	link.target = "_blank";
	link.rel = "noopener noreferrer";
	footer.appendChild(link);
	region.appendChild(footer);
	return region;
}

function postureRow(row) {
	// "flag" shares the "warn" amber; priority is carried by row order, not colour.
	var indicator = { flag: "orange", warn: "orange", tune: "blue" }[row.mark] || "gray";
	var wrap = settingsElement("div", "passkey-posture-row");
	wrap.setAttribute("data-indicator", indicator);
	if (!row.detectable) wrap.classList.add("passkey-posture-note");
	wrap.appendChild(postureMark(row.mark));
	var main = settingsElement("div", "passkey-posture-row-main");
	var problem = settingsElement("div", "passkey-posture-problem");
	problem.appendChild(settingsElement("strong", "", row.what));
	if (row.why) problem.appendChild(settingsElement("span", "passkey-posture-why text-muted", " " + row.why));
	main.appendChild(problem);
	if (row.recommendation) main.appendChild(settingsElement("div", "passkey-posture-fix", row.recommendation));
	wrap.appendChild(main);
	return wrap;
}

// Inline SVG marks: v15's desk sprite lacks many symbols.
var POSTURE_WARNING_MARK = '<path d="M12 3.4 2.3 20.4h19.4z"></path><line x1="12" y1="10" x2="12" y2="14.5"></line><line x1="12" y1="17.4" x2="12" y2="17.5"></line>';
var POSTURE_MARK_SVG = {
	good: '<circle cx="12" cy="12" r="9"></circle><path d="m8.2 12.4 2.6 2.6 5-5.4"></path>',
	flag: POSTURE_WARNING_MARK,
	warn: POSTURE_WARNING_MARK,
	tune: '<circle cx="12" cy="12" r="9"></circle><line x1="8.2" y1="12" x2="15.8" y2="12"></line>',
	note: '<circle cx="12" cy="12" r="9"></circle><line x1="12" y1="11" x2="12" y2="16.4"></line><line x1="12" y1="7.7" x2="12" y2="7.8"></line>',
};

function postureMark(kind) {
	var span = settingsElement("span", "passkey-posture-mark passkey-posture-mark--" + kind);
	span.setAttribute("aria-hidden", "true");
	// Constant artwork (no user data), so innerHTML is safe.
	span.innerHTML = '<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true" ' +
		'style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">' +
		(POSTURE_MARK_SVG[kind] || POSTURE_MARK_SVG.note) + "</svg>";
	return span;
}

// A container at the top of the form, created once per form. The posture host goes
// below the banner host so save-blockers come first.
function settingsFormHost(frm, key, className) {
	if (frm[key] && frm[key].isConnected) return frm[key];
	var mount = frm.layout.wrapper.get(0);
	var host = settingsElement("div", className);
	var banners = frm._passkey_banner_host;
	var after = key !== "_passkey_banner_host" && banners && banners.isConnected ? banners : null;
	mount.insertBefore(host, after ? after.nextSibling : mount.firstChild);
	frm[key] = host;
	return host;
}

function paintBanners(frm) {
	var M = frappe.passkeys_manage_common;
	var host = settingsFormHost(frm, "_passkey_banner_host", "passkey-settings-banners");
	var ctx = buildContext(frm);
	var order = { error: 0, warning: 1, info: 2 };
	var banners = M.settingsBanners(frm.doc, ctx).sort(function (a, b) { return order[a.level] - order[b.level]; });
	fillHost(host, banners.map(function (bn) {
		return bannerEl(bn.level, M.format(__(bn.key), bn.args || []));
	}));
	paintResolvedConfig(frm, ctx);
}

// The resolved RP ID + origins in the resolved_rp_html field. Values enter as text nodes
// before the .html() sink, so free-text passkey_origins can never inject markup.
function paintResolvedConfig(frm, ctx) {
	var field = frm.get_field("resolved_rp_html");
	if (!field) return;
	var rpId = ctx.resolvedRpId;
	var origins = ctx.resolvedOrigins.length ? ctx.resolvedOrigins : null;
	if (!rpId && !origins) {
		field.html(); // nothing resolves yet: the field's own static note
		return;
	}
	var line = settingsElement("p", "text-muted small");
	line.style.margin = "0";
	if (rpId) {
		line.appendChild(document.createTextNode(__("Resolves to") + ": "));
		line.appendChild(settingsElement("strong", "", rpId));
	}
	if (origins) {
		line.appendChild(document.createTextNode((rpId ? " · " : "") + __("Origins: {0}", [origins.join(", ")])));
	}
	var box = settingsElement("div");
	box.appendChild(line);
	field.html(box.innerHTML);
}

function bannerEl(level, msg) {
	var div = settingsElement("div", "passkey-settings-banner alert alert-" +
		{ error: "danger", warning: "warning", info: "info" }[level], msg);
	div.setAttribute("role", level === "info" ? "status" : "alert");
	div.setAttribute("data-indicator", { error: "red", warning: "orange", info: "blue" }[level]);
	return div;
}

// The settingsBanners context. Cross-flag data comes from boot.passkeys.settings_context,
// which the server sends to System Managers.
function buildContext(frm) {
	var boot = frappe.boot.passkeys || {};
	var sc = boot.settings_context || {};
	// Mirrors policy.resolve_rp_id: the explicit RP ID, else the server's resolution.
	// Never window.location.hostname, which is not what the server uses.
	var explicit = (frm.doc.passkey_rp_id || "").trim().toLowerCase();
	var serverRpId = frm._passkey_server_rpid !== undefined ? frm._passkey_server_rpid : boot.rp_id;
	var siteOrigin = frm._passkey_server_site_origin !== undefined
		? frm._passkey_server_site_origin
		: sc.configured_site_origin;
	return {
		currentHost: window.location.hostname,
		currentOrigin: window.location.origin,
		resolvedRpId: explicit || serverRpId || null,
		resolvedOrigins: frappe.passkeys_manage_common.deriveOrigins(frm.doc.passkey_origins, siteOrigin),
		coreTwoFactor: sc.core_two_factor_auth,
		disablePassLogin: sc.disable_user_pass_login,
		passkeyOnlyUserCount: sc.passkey_only_user_count,
		wouldBeBlockedCount: sc.would_be_blocked_count,
	};
}

// Replace a host's children; every repaint starts clean.
function fillHost(host, nodes) {
	host.textContent = "";
	nodes.forEach(function (node) { host.appendChild(node); });
}

function settingsElement(tag, className, text) {
	var node = document.createElement(tag);
	if (className) node.className = className;
	if (text != null) node.textContent = text;
	return node;
}
