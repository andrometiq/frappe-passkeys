// user_passkeys.js — the "Passkeys" section on the Desk User form (DESIGN-v1
// §8.1). Wired via `doctype_js = {"User": "public/js/user_passkeys.js"}` (see the
// build manifest). Renders beside core's "Reset OTP Secret" precedent
// (frappe/core/doctype/user/user.js). Own form ⇒ full interactive cards + add;
// another user's form (System Manager) ⇒ read-only inventory + a link to the
// WebAuthn Credential DocType for admin disable/delete (§8.6). Destination on core
// merge: the passkeys section inside frappe/core/doctype/user/user.js.
//
// All rendering is delegated to frappe.passkeys.manage (passkey_desk.bundle.js),
// which loads first via app_include_js. This file is only the form glue.
//
// eslint-env browser
frappe.ui.form.on("User", {
	refresh: function (frm) {
		var manage = frappe.passkeys && frappe.passkeys.manage;
		if (!manage) return; // desk bundle not loaded (disabled site) ⇒ no section
		if (frm.is_new()) return;

		var t = (frappe._ || function (s) { return s; });
		var boot = frappe.boot && frappe.boot.passkeys;
		// Management surfaces gate on ANY passkey mode (§3.0 matrix): a 2FA-only site
		// still shows them (enabled == true); both modes off — or a dormant /
		// uninstalled app (no bootinfo) — removes the section.
		if (!boot || boot.enabled === false) return;

		var isSelf = frm.doc.name === frappe.session.user;
		if (!isSelf && !frappe.user.has_role("System Manager")) return; // no section for others

		// Mount into a dashboard section we own. add_section() appends, so guard it
		// to run ONCE per form (refresh fires repeatedly) and reuse the host after.
		var host = frm._passkey_host && frm._passkey_host.isConnected ? frm._passkey_host : null;
		if (!host) {
			var $host = frm.dashboard.add_section("", t("Passkeys"));
			host = $host && $host.get ? $host.get(0) : $host;
			if (!host) return;
			frm._passkey_host = host;
		}
		// Clear any prior render (refresh / user navigation).
		while (host.firstChild) host.removeChild(host.firstChild);

		var root = document.createElement("div");
		if (isSelf) {
			root.className = "passkey-cards-root";
			host.appendChild(root);
			manage.renderCards(root, { root: root });
			if (!frm._passkey_change_bound) {
				frm._passkey_change_bound = true;
				// keep the section fresh after add/rename/delete elsewhere
				document.addEventListener("passkey:changed", function onChange() {
					if (!frm._passkey_host || !frm._passkey_host.isConnected) {
						document.removeEventListener("passkey:changed", onChange);
						return;
					}
					var r = frm._passkey_host.querySelector(".passkey-cards-root");
					if (r) manage.renderCards(r, { root: r });
				});
			}
		} else {
			root.className = "passkey-admin-inventory";
			host.appendChild(root);
			manage.renderReadOnlyInventory(root, frm.doc.name);
		}
	},
});
