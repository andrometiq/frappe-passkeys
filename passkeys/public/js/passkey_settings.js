// passkey_settings.js — the Passkey Settings form UX. Wired via
// `doctype_js = {"Passkey Settings": "public/js/passkey_settings.js"}`. Renders
// the banner/dialog matrix on the settings form and
// puts the loud one-way-door confirm on the RP-ID field. Destination on core merge:
// the passkey section of frappe/core/doctype/system_settings/system_settings.js.
//
// The banner DECISIONS come from passkey_manage_common.bundle.js::settingsBanners (pure,
// node-tested); this file only paints them and wires the confirm dialog. Cross-flag
// context (core enable_two_factor_auth / disable_user_pass_login / the passkey-only
// user count) is read from frappe.boot.passkeys.settings_context when the server
// provides it.
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
		// (same idiom as the desk nudge dialog + passkey_confirm.bundle.js::wireCancel).
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

// The hosted "why passkeys" explainer — the theory page the report footer points to
// (opened in a new tab; never iframed, per the CSP-fragility note).
var POSTURE_THEORY_URL = "https://andrometiq.github.io/frappe-passkeys/why-passkeys.html";

// Fetch + paint the admin security-posture report (System-Manager-gated, read-only
// endpoint). The view-model is PURE (M.postureReport) fed by the server rows; this only
// paints it: a compact status card that lands the verdict at a glance — a satisfying
// tick when everything is fine, a loud flag when a passkey can be bypassed — with a
// call-to-action that reveals the full designed checklist in place. States rendered:
// loading, all-clear (good), gaps (high), passkeys-not-active (info), and a calm
// "unavailable" note on error. On any failure the surface degrades quietly (no worse
// than before it existed).
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

// A quiet single-line card (loading / unavailable) — same shell as the verdict card so
// the surface never jumps as it settles.
function postureNoticeCard(markKind, text) {
	var card = postureCardShell("gray", markKind);
	card.classList.add("passkey-posture-card--muted");
	card.appendChild(postureCardBody(__("Security posture"), text, false));
	return card;
}

// The compact verdict card + the collapsible full report. The card always carries the
// verdict text, so the point lands even before the CTA is clicked; the CTA reveals the
// per-check breakdown + the theory link in place.
function paintPostureReport(host, report) {
	var summary = report.summary;
	var tone = summary.tone; // "good" | "high" | "info"
	var indicator = tone === "high" ? "red" : tone === "good" ? "green" : "blue";
	var markKind = tone === "high" ? "flag" : tone === "good" ? "good" : "note";

	var card = postureCardShell(indicator, markKind);
	card.classList.add("passkey-posture-card--" + tone);
	card.appendChild(postureCardBody(__("Security posture"), report.headline.text || __("Security posture"), summary.canBypass));

	var region = buildPostureReportRegion(report);
	region.hidden = true;

	// The CTA: a satisfying "view report" in the calm states, a loud "Review N gaps" when
	// a passkey can be bypassed. Toggles the in-place report (aria-expanded on the button).
	var gapLabel = summary.actionCount === 1 ? __("1 gap") : __("{0} gaps", [summary.actionCount]);
	var ctaOpen = summary.canBypass && summary.actionCount ? __("Review {0}", [gapLabel]) : __("View report");
	var ctaClose = __("Hide report");
	var cta = document.createElement("button");
	cta.type = "button";
	cta.className = "btn btn-sm passkey-posture-cta " + (tone === "high" ? "btn-danger" : "btn-default");
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

	// Footer: the hosted theory explainer. A plain link opened in a new tab — external
	// URL, so no iframe (avoids CSP fragility); noopener/noreferrer on the new tab.
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
	var indicator = row.mark === "flag" ? "red"
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

// The tick/flag glyphs. App-shipped inline SVG (lucide-style artwork, stroke=currentColor)
// — NEVER a desk "#icon-*" sprite href (v15's sprite lacks many symbols), so the mark
// renders identically on v15 / v16 / develop and colours itself from the row indicator.
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
	// Constant artwork (no user data) — safe to set as innerHTML, same idiom as
	// passkey_common.js::iconSvg / the desk bundle's glyph render.
	span.innerHTML = '<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true" ' +
		'style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round">' +
		(POSTURE_MARK_SVG[kind] || POSTURE_MARK_SVG.note) + "</svg>";
	return span;
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
