// The server publishes RP diagnostics only to System Managers.
(function (root) {
	"use strict";

	function rpAlertDecision(alert) {
		if (!alert || !alert.reason) return null;
		var message;
		var args = [alert.site_host, alert.rp_id];
		if (alert.reason === "no_rp_id") {
			message = "Passkeys are off on this site: no RP ID resolves. Passkey requirements are paused. Set host_name in site config or a Passkey RP ID.";
			args = [];
		} else if (alert.reason === "no_valid_origins") {
			message = "Passkeys are off on this site: none of its origins is inside the RP ID {0}. Passkey requirements are paused until this is fixed.";
			args = [alert.rp_id];
		} else if (alert.reason === "host_outside_rp") {
			if (alert.status === "off") {
				message = "Passkeys are off on this site: its address {0} isn't covered by the RP ID {1}. Passkey requirements are paused until this is fixed.";
			} else if (alert.status === "app_only") {
				message = "Web sign-in on this site has no passkey path: its address {0} isn't covered by the RP ID {1}. Only the mobile app can use passkeys, and passkey requirements still apply.";
			} else if (alert.status === "web_works") {
				message = "This site's address {0} isn't covered by the RP ID {1}. Passkeys work only at: {2}.";
				args.push((alert.working_origins || []).join(", "));
			}
		}
		if (!message) return null;
		return { message: message, args: args, suggestion: alert.suggested_rp_id,
			action: alert.reason === "no_rp_id" ? "Open Passkey Settings" : "Fix in Passkey Settings" };
	}

	if (typeof module === "object" && module.exports) module.exports = { rpAlertDecision: rpAlertDecision };
	if (!root || !root.frappe) return;
	var frappe = root.frappe;
	frappe.passkeys_site_alert = { rpAlertDecision: rpAlertDecision };
	var dismissed = false;
	function render() {
		var alert = frappe.boot && frappe.boot.passkeys && frappe.boot.passkeys.rp_alert;
		var decision = rpAlertDecision(alert);
		if (!decision || dismissed || document.querySelector(".passkey-site-alert")) return;
		var key = "passkeys:rp_alert:" + (frappe.session && frappe.session.user || "") + ":" + JSON.stringify(alert);
		try { if (root.sessionStorage.getItem(key)) return; } catch (_) { /* Storage may be unavailable. */ }
		var mount = document.querySelector(".main-section") || document.querySelector("#body");
		if (!mount) return;
		var bar = document.createElement("div");
		bar.className = "passkey-site-alert alert alert-warning";
		bar.setAttribute("role", "status");
		bar.setAttribute("data-indicator", "orange");
		var text = document.createElement("span");
		text.textContent = __(decision.message, decision.args);
		bar.appendChild(text);
		var fix = document.createElement("button");
		fix.type = "button";
		fix.className = "btn btn-xs btn-default ml-2";
		fix.textContent = __(decision.action);
		fix.addEventListener("click", function () {
			try {
				if (decision.suggestion) root.sessionStorage.setItem("passkeys:suggest_rp_id", decision.suggestion);
			} catch (_) { /* The settings link still works without storage. */ }
			frappe.set_route("Form", "Passkey Settings");
		});
		bar.appendChild(fix);
		var close = document.createElement("button");
		close.type = "button";
		close.className = "close ml-2";
		close.textContent = "×";
		close.setAttribute("aria-label", __("Dismiss"));
		close.addEventListener("click", function () {
			dismissed = true;
			try { root.sessionStorage.setItem(key, "1"); } catch (_) { /* Keep the in-memory dismissal. */ }
			bar.remove();
		});
		bar.appendChild(close);
		mount.insertBefore(bar, mount.firstChild);
	}
	if (typeof frappe.after_ajax === "function") frappe.after_ajax(function () {
		render();
		if (typeof root.$ === "function") root.$(document).on("page-change", render);
	});
	else if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", render);
	else render();
})(typeof window !== "undefined" ? window : null);
