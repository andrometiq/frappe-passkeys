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
		paintMobileFieldDescriptions(frm);
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

// Fetch the RP ID the server resolves right now (System-Manager-gated, read-only
// endpoint). Cached on the form and read by buildContext; on failure we fall back to
// frappe.boot.passkeys.rp_id, so the display is never worse than boot.
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

// The hosted "why passkeys" explainer — the theory page the report footer points to
// (opened in a new tab; never iframed, per the CSP-fragility note).
var POSTURE_THEORY_URL = "https://andrometiq.github.io/frappe-passkeys/why-passkeys.html";

// Fetch + paint the admin security-posture report (System-Manager-gated, read-only
// endpoint). The view-model is PURE (M.postureReport) fed by the server rows; this only
// paints it: a compact status card that lands the verdict at a glance — a satisfying
// tick when everything is fine, otherwise a calm "here are some recommendations" card
// (never alarm-red) — with a call-to-action that reveals the full designed checklist in
// place. States rendered:
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
	// Calm, never alarmist (the owner's principle): the posture surface has NO alarm-red.
	// A clean site is a satisfying green tick; anything else is a calm BLUE "here are some
	// recommendations" card — a bypass path is a recommendation, not an emergency. Red is
	// reserved for the genuine save-blocking errors in the banner host ABOVE this card.
	var indicator = tone === "good" ? "green" : tone === "high" ? "blue" : "gray";
	var markKind = tone === "good" ? "good" : "note"; // tick for all-clear, info-circle otherwise

	var card = postureCardShell(indicator, markKind);
	card.classList.add("passkey-posture-card--" + tone);
	// role="status", not "alert" (last arg false): a recommendation is announced politely,
	// never as an assertive interruption (the screen-reader equivalent of the rejected red).
	card.appendChild(postureCardBody(__("Security posture"), report.headline.text || __("Security posture"), false));

	var region = buildPostureReportRegion(report);
	region.hidden = true;

	// The CTA: "View recommendations" when there are hardening suggestions, "View report"
	// when all-clear. NO "Review N gaps" count — the numeric gap badge read like a virus
	// scanner (and the collapsed report already lists the rows). Always btn-default, never
	// btn-danger — this surface never alarms. Toggles the in-place report (aria-expanded).
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
	// No alarm-red here either — a "flag" (high-severity bypass path) shares the "warn"
	// amber; this is a calm recommendations list, priority carried by row order not colour.
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

// A self-managed posture container, mounted just BELOW the banner host so a genuine (red)
// save-blocker in the banners always outranks the calm recommendations card — real
// problems first. Cleared on every paint (never stacks duplicates).
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
	// The resolved RP ID / origins echo is NOT a top banner anymore — it renders inline in
	// the "Resolved Configuration" field, right next to the RP-ID / origins fields.
	paintResolvedConfig(frm, ctx);
}

// Render the resolved RP ID + origins INLINE in the "Resolved Configuration" HTML field
// (resolved_rp_html), which sits directly below the RP-ID / origins fields — the subtle,
// near-the-field home the owner asked for, instead of a top banner. Dynamic values go in
// as DOM text nodes (auto-escaped) before the field's .html() sink, so free-text
// passkey_origins can never inject markup.
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

// Resolve the settings context. RP ID is credential scope. Trusted origins are the
// exact configured site origin supplied by the server plus explicit passkey_origins;
// an RP apex is never inferred as an origin. Cross-flag data rides
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
	var configuredSiteOrigin = frm._passkey_server_site_origin !== undefined
		? frm._passkey_server_site_origin
		: (sc.configured_site_origin || sc.site_origin || boot.configured_site_origin || boot.site_origin || null);
	var origins = parseOrigins(frm.doc.passkey_origins, configuredSiteOrigin);
	return {
		currentHost: host,
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

// Derive the resolved origins the same way the server does (policy.resolve_origins):
// exact configured site origin first, then explicit custom lines. RP ID is never used.
// Delegates to the pure, node-tested helper so this stays a thin DOM glue file.
function parseOrigins(raw, configuredSiteOrigin) {
	var M = typeof frappe !== "undefined" && frappe.passkeys_manage_common;
	if (M && M.deriveOrigins) return M.deriveOrigins(raw, configuredSiteOrigin);
	var lines = String(raw || "").split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
	if (configuredSiteOrigin && lines.indexOf(configuredSiteOrigin) === -1) lines.unshift(configuredSiteOrigin);
	return lines;
}
