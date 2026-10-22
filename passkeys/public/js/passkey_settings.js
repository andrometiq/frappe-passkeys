// The Passkey Settings form: the banners from passkey_manage_common's settingsBanners,
// the security-posture report and the RP-ID impact confirmation.
// eslint-env browser
frappe.ui.form.on("Passkey Settings", {
	refresh: function (frm) {
		// The last-saved RP ID, for reverting a backed-out change (refresh re-fires on save).
		frm._passkey_rpid_saved = frm.doc.passkey_rp_id;
		if (!(frm.is_dirty && frm.is_dirty())) frm._passkey_rp_saved = rpCandidate(frm);
		frm.set_df_property("passkey_app_origins", "description", __(
			"Native Android app origins may be listed here as android:apk-key-hash:<hash>. iOS needs no Trusted App Origin entry here; configure the exact HTTPS origin asserted by the iOS app under Passkey Origins. RP ID is credential scope, not an origin."
		));
		var rpIdField = frm.fields_dict.passkey_rp_id;
		if (rpIdField && rpIdField.$input) {
			rpIdField.$input.off("blur.passkeys").on("blur.passkeys", function () {
				// The control writes typed text to the doc on a debounce; commit it before comparing.
				Promise.resolve(frm.set_value("passkey_rp_id", rpIdField.get_input_value() || ""))
					.then(function () { confirmRpIdChange(frm); });
			});
		}
		paintBanners(frm);
		fetchResolvedRpId(frm); // repaints when it lands
		fetchSettingsContext(frm);
		fetchSecurityPosture(frm); // the verdict reads SAVED state
		pickupRpSuggestion(frm);
	},
	after_save: function (frm) {
		frm._passkey_rpid_suggestion = null;
		pollEnforcementPreview(frm, frm.doc.__onload && frm.doc.__onload.passkeys_preview_after_scan);
	},
	// Repaint on any knob change so the banners stay live before save.
	login_with_passkey: paintBanners,
	passkey_as_second_factor: paintBanners,
	passkey_notify_on_change: paintBanners,
	passkey_origins: paintBanners,
	passkey_app_origins: paintBanners,
	passkey_everyone_else: paintBanners,
	passkey_enforce_after: paintBanners,
	passkey_enforce_scope: paintBanners,
	passkey_enforce_roles: paintBanners,
	passkey_enforce_privileged_always: paintBanners,
	passkey_enforce_incapable: paintBanners,
	validate: function (frm) {
		if (rpIdChangeUnconfirmed(frm)) {
			frappe.validated = false;
			confirmRpIdChange(frm);
			return;
		}
		var result = frappe.passkeys_manage_common.validateAndroidFingerprints(frm.doc.passkey_android_cert_fingerprints);
		if (!result.valid) {
			frappe.throw(__(
				"Each Android signing-certificate fingerprint must contain exactly 64 hexadecimal characters; colons and a SHA-256 label are optional. Invalid line(s): {0}",
				[result.invalid.join(", ")]
			));
		}
	},
	// Repaint per keystroke; the impact confirmation waits for blur (or save), so typing
	// a new RP ID raises it once, not once per character.
	passkey_rp_id: paintBanners,
});

function rpIdChangeUnconfirmed(frm) {
	var value = frm.doc.passkey_rp_id || "";
	var saved = (frm.doc_before_save && frm.doc_before_save.passkey_rp_id) || frm._passkey_rpid_saved || "";
	return !frm.doc.__islocal && value !== saved && frm._passkey_rpid_ack !== rpCandidate(frm);
}

function rpCandidate(frm) {
	return JSON.stringify([frm.doc.passkey_rp_id || "", frm.doc.passkey_origins || "", frm.doc.passkey_app_origins || ""]);
}

function hasUnsavedRpConfig(frm) {
	return rpCandidate(frm) !== frm._passkey_rp_saved;
}

function confirmRpIdChange(frm) {
	if (!rpIdChangeUnconfirmed(frm) || frm._passkey_rpid_dialog_open) return;
	var saved = (frm.doc_before_save && frm.doc_before_save.passkey_rp_id) || frm._passkey_rpid_saved || "";
	var value = frm.doc.passkey_rp_id || "";
	var candidate = rpCandidate(frm);
	frm._passkey_rpid_dialog_open = true;
	frm._passkey_rpid_error = null;
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_rp_id_change_impact",
		args: { rp_id: value, passkey_origins: frm.doc.passkey_origins || "", passkey_app_origins: frm.doc.passkey_app_origins || "" },
		callback: function (r) {
			if (candidate !== rpCandidate(frm) || !r || !r.message) {
				frm._passkey_rpid_dialog_open = false;
				return;
			}
			var proceeded = false;
			var d = frappe.warn(__("Change the RP ID?"), rpImpactMessage(r.message), function () {
				proceeded = true;
				if (candidate === rpCandidate(frm)) frm._passkey_rpid_ack = candidate;
			}, __("Yes, change it"), true);
			d.$wrapper.on("hide.bs.modal", function () {
				frm._passkey_rpid_dialog_open = false;
				if (!proceeded && candidate === rpCandidate(frm)) frm.set_value("passkey_rp_id", saved);
			});
		},
		error: function (r) {
			frm._passkey_rpid_dialog_open = false;
			if (candidate !== rpCandidate(frm)) return;
			var body = r.responseJSON || r;
			if (body.exc_type !== "ValidationError") return;
			frm._passkey_rpid_error_candidate = candidate;
			frm._passkey_rpid_error = frappe.passkeys_common.serverMessages(body) || __("Check the RP ID and origins.");
			paintBanners(frm);
		},
	});
}

function rpImpactMessage(impact) {
	var lines = [__(frappe.passkeys_manage_common.COPY.rpIdOneWayDoor)];
	lines.push(impact.stop.passkeys ? __("{0} passkey(s) of {1} user(s) will stop working on this site.",
		[impact.stop.passkeys, impact.stop.users]) : __("No passkeys stop working."));
	if (impact.start.passkeys) lines.push(__("{0} passkey(s) of {1} user(s) made for {2} will work again.",
		[impact.start.passkeys, impact.start.users, impact.new_rp_id]));
	if (impact.new_off) lines.push(__("Passkeys would be off on this site with this RP ID."));
	return lines.map(function (line) { return frappe.passkeys_common.escapeHtml(line); }).join("<br>");
}

function pickupRpSuggestion(frm) {
	var storage;
	var value;
	try {
		storage = window.sessionStorage;
		value = storage && storage.getItem("passkeys:suggest_rp_id");
		if (value) storage.removeItem("passkeys:suggest_rp_id");
	} catch (_) { return; }
	if (!value) return;
	frm._passkey_rpid_suggestion = value;
	Promise.resolve(frm.set_value("passkey_rp_id", value)).then(function () {
		paintBanners(frm);
		frm.scroll_to_field("passkey_rp_id");
	});
}

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

function fetchSettingsContext(frm, onContext) {
	var doc = frm.doc;
	var modified = doc.modified;
	var request = (frm._passkey_context_request || 0) + 1;
	frm._passkey_context_request = request;
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.get_settings_context",
		callback: function (r) {
			if (frm.doc !== doc || doc.modified !== modified) return;
			var result = request === frm._passkey_context_request && r && r.message;
			if (onContext) return onContext(result);
			if (!result) return;
			frm._passkey_settings_context = result;
			paintBanners(frm);
		},
	});
}

function recalculateEnforcementPreview(frm, button) {
	frappe.call({
		method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.recalculate_enforcement_preview",
		btn: $(button),
		callback: function (response) {
			frappe.show_alert({ message: __("Recounting in the background…"), indicator: "blue" });
			pollEnforcementPreview(frm, response.message.after_scan);
		},
	});
}

function pollEnforcementPreview(frm, threshold) {
	var doc = frm.doc;
	var modified = doc.modified;
	var attempts = 0;
	var poll = {};
	if (frm._passkey_preview_poll) clearTimeout(frm._passkey_preview_poll.timer);
	frm._passkey_preview_poll = poll;
	function isCurrent() {
		return frm._passkey_preview_poll === poll && frm.doc === doc &&
			doc.modified === modified && !(frm.is_dirty && frm.is_dirty());
	}
	function schedule() {
		poll.timer = setTimeout(function () {
			if (!isCurrent()) return;
			attempts += 1;
			fetchSettingsContext(frm, function (result) {
				if (!isCurrent()) return;
				if (result) {
					frm._passkey_settings_context = result;
					paintBanners(frm);
					var preview = result.enforcement_preview;
					if (preview && typeof threshold === "number" && Number(preview.scan) > threshold) return;
				}
				if (attempts < 10) schedule();
			});
		}, 3000);
	}
	schedule();
}

// The hosted explainer the report footer links to (new tab, never iframed).
var POSTURE_THEORY_URL = "https://andrometiq.com/software/passkey/why-passkeys-are-safer/";

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
		var banner = bannerEl(bn.level, M.format(__(bn.key), bn.args || []));
		if (bn.muted) banner.classList.add("text-muted");
		if (bn.action === "recalculate") {
			var button = settingsElement("button", "btn btn-xs btn-default ml-2", __("Recalculate"));
			button.type = "button";
			button.addEventListener("click", function () { recalculateEnforcementPreview(frm, button); });
			banner.appendChild(button);
		}
		return banner;
	}));
	paintResolvedConfig(frm, ctx);
}

// The resolved RP ID + origins in the resolved_rp_html field. Values enter as text nodes
// before the .html() sink, so free-text passkey_origins can never inject markup.
function paintResolvedConfig(frm, ctx) {
	var field = frm.get_field("resolved_rp_html");
	if (!field) return;
	if (frm._passkey_rpid_error_candidate !== rpCandidate(frm)) frm._passkey_rpid_error = null;
	var input = frm.fields_dict.passkey_rp_id && frm.fields_dict.passkey_rp_id.$input;
	if (input) input.attr("aria-invalid", frm._passkey_rpid_error ? "true" : "false");
	var rpId = ctx.resolvedRpId;
	var origins = ctx.resolvedOrigins.length ? ctx.resolvedOrigins : null;
	if (!rpId && !origins && !frm._passkey_rpid_suggestion && !frm._passkey_rpid_error) {
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
	if (frm._passkey_rpid_suggestion) box.appendChild(settingsElement("p", "text-muted small",
		__("Suggested from this site's address ({0}). Review it, then save.", [frm._passkey_rpid_suggestion])));
	if (frm._passkey_rpid_error) {
		var error = settingsElement("p", "help-box", frm._passkey_rpid_error);
		error.setAttribute("role", "alert");
		box.appendChild(error);
	}
	var stale = (frm._passkey_settings_context || {}).stale_passkeys;
	var canRemove = stale && stale.removable && !frappe.passkeys_manage_common.isImpersonated((frappe.boot || {}).passkeys);
	if (stale && stale.passkeys) {
		var staleLine = settingsElement("p", "text-muted small", __("{0} passkey(s) of {1} user(s) were made for another RP ID and don't work on this site.", [stale.passkeys, stale.users]));
		if (canRemove) {
			var button = settingsElement("button", "btn btn-xs btn-default ml-2 passkey-remove-stale", __("Remove stale passkeys"));
			button.type = "button";
			button.disabled = hasUnsavedRpConfig(frm);
			staleLine.appendChild(button);
			if (button.disabled) staleLine.appendChild(settingsElement("span", "text-muted small ml-2",
				__("Save the RP ID change first.")));
		}
		box.appendChild(staleLine);
	}
	field.html(box.innerHTML);
	if (canRemove) field.$wrapper.find(".passkey-remove-stale").on("click", function () { removeStalePasskeys(frm, stale); });
}

function bannerEl(level, msg) {
	var div = settingsElement("div", "passkey-settings-banner alert alert-" +
		{ error: "danger", warning: "warning", info: "info" }[level], msg);
	div.setAttribute("role", level === "info" ? "status" : "alert");
	div.setAttribute("data-indicator", { error: "red", warning: "orange", info: "blue" }[level]);
	return div;
}

// Cross-flag data is fetched only when the settings form opens.
function buildContext(frm) {
	var boot = frappe.boot.passkeys || {};
	var sc = frm._passkey_settings_context || {};
	// Mirrors policy.resolve_rp_id: the explicit RP ID, else the server's resolution.
	// Never window.location.hostname, which is not what the server uses.
	var explicit = (frm.doc.passkey_rp_id || "").trim().toLowerCase();
	var serverRpId = frm._passkey_server_rpid !== undefined ? frm._passkey_server_rpid : boot.rp_id;
	var siteOrigin = frm._passkey_server_site_origin;
	return {
		currentHost: window.location.hostname,
		currentOrigin: window.location.origin,
		resolvedRpId: explicit || serverRpId || null,
		resolvedOrigins: frappe.passkeys_manage_common.deriveOrigins(frm.doc.passkey_origins, siteOrigin),
		coreTwoFactor: sc.core_two_factor_auth,
		disablePassLogin: sc.disable_user_pass_login,
		passkeyOnlyUserCount: sc.passkey_only_user_count,
		enforcementPreview: sc.enforcement_preview && {
			count: sc.enforcement_preview.count,
			computed_at: frappe.datetime.str_to_user(sc.enforcement_preview.computed_at),
		},
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

function removeStalePasskeys(frm, stale) {
	if (hasUnsavedRpConfig(frm)) return;
	var dialog = new frappe.ui.Dialog({
		title: __("Remove stale passkeys?"),
		fields: [{ fieldtype: "HTML", options: frappe.passkeys_common.escapeHtml(__("Remove {0} passkey(s) that don't work with the saved RP ID {1}? Their owners get the usual email that a passkey was removed. Flagged passkeys are kept for review. This can't be undone.", [stale.removable, stale.site_rp_id])) }],
		primary_action_label: __("Remove passkeys"),
		primary_action: function () {
			if (hasUnsavedRpConfig(frm)) return;
			frappe.call({
				method: "passkeys.passkeys.doctype.passkey_settings.passkey_settings.remove_stale_passkeys",
				args: { site_rp_id: stale.site_rp_id },
				btn: dialog.get_primary_btn(),
				callback: function (r) {
					dialog.hide();
					frappe.show_alert({ message: __("Removed {0} passkey(s).", [r.message.removed]), indicator: "green" });
					fetchSettingsContext(frm);
				},
			});
		},
	});
	dialog.show();
}
