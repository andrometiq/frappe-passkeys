// passkey_settings.js — the Passkey Settings form: paints the banners decided by
// passkey_manage_common.bundle.js::settingsBanners, the posture report and the RP-ID
// one-way-door confirm.
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
		paintMobileFieldDescriptions(frm);
		paintBanners(frm, M);
		// The RP ID the server resolves now (boot can be stale); repaints when it lands.
		fetchResolvedRpId(frm);
		// The posture verdict reads SAVED state, so fetch on refresh (also after save).
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
	passkey_enforce_privileged_always: repaint,
	passkey_enforce_incapable: repaint,
	validate: function (frm) {
		var M = frappe.passkeys_manage_common;
		if (!M || typeof M.validateAndroidFingerprints !== "function") return;
		var result = M.validateAndroidFingerprints(frm.doc.passkey_android_cert_fingerprints);
		if (!result.valid) {
			frappe.throw(__(
				"Each Android signing-certificate fingerprint must contain exactly 64 hexadecimal characters; colons and a SHA-256 label are optional. Invalid line(s): {0}",
				[result.invalid.join(", ")]
			));
		}
	},
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
		// Any dismissal MUST revert the field so a backed-out change can never be saved.
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

function paintMobileFieldDescriptions(frm) {
	if (!frm.set_df_property) return;
	frm.set_df_property("passkey_app_origins", "description", __(
		"Native Android app origins may be listed here as android:apk-key-hash:<hash>. iOS needs no Trusted App Origin entry here; configure the exact HTTPS origin asserted by the iOS app under Passkey Origins. RP ID is credential scope, not an origin."
	));
}

function repaint(frm) {
	var M = frappe.passkeys_manage_common;
	if (M) paintBanners(frm, M);
}

// Fetch the RP ID the server resolves now; on failure buildContext falls back to boot.
function fetchResolvedRpId(frm) {
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_resolved_rp_id",
		callback: function (r) {
			if (!r || !r.message) return;
			frm._passkey_server_rpid = r.message.rp_id || null;
			// Newer servers return the exact configured host_name origin. Accept the
			// transition aliases but never synthesize an origin from the RP ID.
			frm._passkey_server_site_origin = r.message.configured_site_origin ||
				r.message.site_origin || r.message.exact_site_origin || null;
			frm._passkey_host_name_configured = !!r.message.host_name_configured;
			repaint(frm);
		},
	});
}

// The hosted explainer the report footer links to (new tab, never iframed).
var POSTURE_THEORY_URL = "https://andrometiq.github.io/frappe-passkeys/why-passkeys.html";

// Fetch + paint the security-posture report (view-model: M.postureReport). States:
// loading, all-clear, gaps, passkeys-not-active, and a quiet "unavailable" on error.
function fetchSecurityPosture(frm, M) {
	if (!M.postureReport) return;
	renderPostureState(frm, { state: "loading" });
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_security_posture",
		callback: function (r) {
			if (!r || !r.message) { renderPostureState(frm, { state: "error" }); return; }
			renderPostureState(frm, { state: "ready", report: M.postureReport(r.message) });
		},
		error: function () { renderPostureState(frm, { state: "error" }); },
	});
}

function renderPostureState(frm, opts) {
	var host = postureHost(frm);
	if (!host) return;
	while (host.firstChild) host.removeChild(host.firstChild); // idempotent across repaints
	if (opts.state === "loading") {
		host.appendChild(postureNoticeCard("note", __("Checking your security posture…")));
		return;
	}
	if (opts.state === "error") {
		host.appendChild(postureNoticeCard("note", __("The security report couldn’t be loaded right now.")));
		return;
	}
	paintPostureReport(host, opts.report);
}

// A single-line card (loading / unavailable) in the verdict card's shell, so nothing jumps.
function postureNoticeCard(markKind, text) {
	var card = postureCardShell("gray", markKind);
	card.classList.add("passkey-posture-card--muted");
	card.appendChild(postureCardBody(__("Security posture"), text, false));
	return card;
}

// The verdict card + the collapsible full report.
function paintPostureReport(host, report) {
	var summary = report.summary;
	var tone = summary.tone; // "good" | "high" | "info"
	// No red here: a bypass path is a recommendation. Red is kept for the save-blocking
	// banners above this card.
	var indicator = tone === "good" ? "green" : tone === "high" ? "blue" : "gray";
	var markKind = tone === "good" ? "good" : "note"; // tick for all-clear, info-circle otherwise

	var card = postureCardShell(indicator, markKind);
	card.classList.add("passkey-posture-card--" + tone);
	// role="status", not "alert": a recommendation is announced politely.
	card.appendChild(postureCardBody(__("Security posture"), report.headline.text || __("Security posture"), false));

	var region = buildPostureReportRegion(report);
	region.hidden = true;

	// "View recommendations" or, when all-clear, "View report"; toggles the report in place.
	var ctaOpen = summary.canBypass ? __("View recommendations") : __("View report");
	var ctaClose = __("Hide report");
	var cta = document.createElement("button");
	cta.type = "button";
	cta.className = "btn btn-sm passkey-posture-cta btn-default";
	cta.setAttribute("aria-expanded", "false");
	cta.setAttribute("aria-controls", region.id);
	cta.textContent = ctaOpen;
	cta.addEventListener("click", function () {
		var open = region.hidden; // about to open?
		region.hidden = !open;
		cta.setAttribute("aria-expanded", open ? "true" : "false");
		cta.textContent = open ? ctaClose : ctaOpen;
	});
	card.appendChild(cta);

	host.appendChild(card);
	host.appendChild(region);
}

// Card shell: the coloured indicator rail + the leading tick/flag mark.
function postureCardShell(indicator, markKind) {
	var card = document.createElement("div");
	card.className = "passkey-posture-card";
	card.setAttribute("data-indicator", indicator);
	card.appendChild(postureMark(markKind));
	return card;
}

// Card body: a small "Security posture" eyebrow + the verdict line. `alert` marks the
// verdict line as an assertive live region when a bypass exists.
function postureCardBody(eyebrowText, verdictText, alert) {
	var body = document.createElement("div");
	body.className = "passkey-posture-headline";
	var eyebrow = document.createElement("div");
	eyebrow.className = "passkey-posture-eyebrow";
	eyebrow.textContent = eyebrowText;
	body.appendChild(eyebrow);
	var verdict = document.createElement("div");
	verdict.className = "passkey-posture-verdict-text";
	verdict.setAttribute("role", alert ? "alert" : "status");
	verdict.textContent = verdictText;
	body.appendChild(verdict);
	return body;
}

function buildPostureReportRegion(report) {
	var region = document.createElement("div");
	region.className = "passkey-posture-report";
	region.id = "passkey-posture-report";

	var heading = document.createElement("div");
	heading.className = "passkey-posture-report-heading";
	heading.textContent = __("What this checks");
	region.appendChild(heading);

	report.rows.forEach(function (row) {
		region.appendChild(postureRowEl(row));
	});

	// Footer: the hosted explainer, in a new tab with noopener/noreferrer.
	var footer = document.createElement("div");
	footer.className = "passkey-posture-footer";
	var link = document.createElement("a");
	link.className = "passkey-posture-theory";
	link.href = POSTURE_THEORY_URL;
	link.target = "_blank";
	link.rel = "noopener noreferrer";
	link.textContent = __("Why passkeys are safer — and when they aren’t →");
	footer.appendChild(link);
	region.appendChild(footer);
	return region;
}

function postureRowEl(row) {
	// "flag" shares the "warn" amber; priority is carried by row order, not colour.
	var indicator = row.mark === "flag" ? "orange"
		: row.mark === "warn" ? "orange"
		: row.mark === "tune" ? "blue" : "gray";
	var wrap = document.createElement("div");
	wrap.className = "passkey-posture-row";
	wrap.setAttribute("data-indicator", indicator);
	if (!row.detectable) wrap.classList.add("passkey-posture-note");

	wrap.appendChild(postureMark(row.mark));

	var main = document.createElement("div");
	main.className = "passkey-posture-row-main";

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
	main.appendChild(problem);

	if (row.recommendation) {
		var fix = document.createElement("div");
		fix.className = "passkey-posture-fix";
		fix.textContent = row.recommendation;
		main.appendChild(fix);
	}
	wrap.appendChild(main);
	return wrap;
}

// The tick/flag glyphs as inline SVG: v15's desk sprite lacks many symbols.
var POSTURE_MARK_SVG = {
	good: '<circle cx="12" cy="12" r="9"></circle><path d="m8.2 12.4 2.6 2.6 5-5.4"></path>',
	flag: '<path d="M12 3.4 2.3 20.4h19.4z"></path><line x1="12" y1="10" x2="12" y2="14.5"></line><line x1="12" y1="17.4" x2="12" y2="17.5"></line>',
	warn: '<path d="M12 3.4 2.3 20.4h19.4z"></path><line x1="12" y1="10" x2="12" y2="14.5"></line><line x1="12" y1="17.4" x2="12" y2="17.5"></line>',
	tune: '<circle cx="12" cy="12" r="9"></circle><line x1="8.2" y1="12" x2="15.8" y2="12"></line>',
	note: '<circle cx="12" cy="12" r="9"></circle><line x1="12" y1="11" x2="12" y2="16.4"></line><line x1="12" y1="7.7" x2="12" y2="7.8"></line>',
};

function postureMark(kind) {
	var span = document.createElement("span");
	span.className = "passkey-posture-mark passkey-posture-mark--" + kind;
	span.setAttribute("aria-hidden", "true");
	// Constant artwork (no user data), so innerHTML is safe.
	span.innerHTML = '<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true" ' +
		'style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">' +
		(POSTURE_MARK_SVG[kind] || POSTURE_MARK_SVG.note) + "</svg>";
	return span;
}

// The posture container, mounted BELOW the banner host so save-blockers come first.
function postureHost(frm) {
	if (frm._passkey_posture_host && frm._passkey_posture_host.isConnected) return frm._passkey_posture_host;
	var $mount = (frm.layout && frm.layout.wrapper) || (frm.dashboard && frm.dashboard.wrapper) || frm.$wrapper;
	var mount = $mount && $mount.get ? $mount.get(0) : $mount;
	if (!mount) return null;
	var host = document.createElement("div");
	host.className = "passkey-posture";
	// Below the banner host when it exists, else at the very top of the form.
	var bannerHostEl = (frm._passkey_banner_host && frm._passkey_banner_host.isConnected)
		? frm._passkey_banner_host : null;
	mount.insertBefore(host, bannerHostEl ? bannerHostEl.nextSibling : mount.firstChild);
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
	paintResolvedConfig(frm, ctx);
}

// Render the resolved RP ID + origins in the resolved_rp_html field. Values go in as text
// nodes before the .html() sink, so free-text passkey_origins can never inject markup.
function paintResolvedConfig(frm, ctx) {
	var field = frm.get_field && frm.get_field("resolved_rp_html");
	if (!field || !field.html) return;
	var rpId = ctx.resolvedRpId;
	var origins = ctx.resolvedOrigins && ctx.resolvedOrigins.length ? ctx.resolvedOrigins : null;
	if (!rpId && !origins) {
		field.html(); // nothing resolves yet — fall back to the field's own static note
		return;
	}
	var line = document.createElement("p");
	line.className = "text-muted small";
	line.style.margin = "0";
	if (rpId) {
		line.appendChild(document.createTextNode(__("Resolves to") + ": "));
		var strong = document.createElement("strong");
		strong.textContent = rpId;
		line.appendChild(strong);
	}
	if (origins) {
		// One translatable unit (no <strong> here, unlike the RP-ID line above) so the label stays localizable.
		line.appendChild(document.createTextNode((rpId ? " · " : "") + __("Origins: {0}", [origins.join(", ")])));
	}
	var box = document.createElement("div");
	box.appendChild(line);
	// box.innerHTML is safe: every dynamic value entered via textContent, so it is escaped.
	field.html(box.innerHTML);
}

// The banner container at the top of the form; cleared on every paint.
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

// The settings context for settingsBanners. Cross-flag data comes from
// frappe.boot.passkeys.settings_context when the server ships it.
function buildContext(frm) {
	var boot = (frappe.boot && frappe.boot.passkeys) || {};
	var sc = boot.settings_context || {};
	var host = window.location && window.location.hostname;
	// Mirrors policy.resolve_rp_id: the explicit RP ID, else the server's host_name
	// resolution. Never window.location.hostname, which is not what the server uses.
	var explicit = (frm.doc.passkey_rp_id || "").trim().toLowerCase();
	var serverResolved = frm._passkey_server_rpid !== undefined
		? frm._passkey_server_rpid
		: (boot.rp_id || null);
	var rpId = explicit || serverResolved || null;
	var configuredSiteOrigin = frm._passkey_server_site_origin !== undefined
		? frm._passkey_server_site_origin
		: (sc.configured_site_origin || sc.site_origin || boot.configured_site_origin || boot.site_origin || null);
	var origins = parseOrigins(frm.doc.passkey_origins, configuredSiteOrigin);
	return {
		currentHost: host,
		currentOrigin: window.location && window.location.origin,
		resolvedRpId: rpId,
		resolvedOrigins: origins,
		configuredSiteOrigin: configuredSiteOrigin,
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

// Resolved origins, as policy.resolve_origins derives them.
function parseOrigins(raw, configuredSiteOrigin) {
	var M = typeof frappe !== "undefined" && frappe.passkeys_manage_common;
	if (M && M.deriveOrigins) return M.deriveOrigins(raw, configuredSiteOrigin);
	var lines = String(raw || "").split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
	if (configuredSiteOrigin && lines.indexOf(configuredSiteOrigin) === -1) lines.unshift(configuredSiteOrigin);
	return lines;
}
