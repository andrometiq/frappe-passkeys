// user_passkeys.js — the "Passkeys" section on the Desk User form. Wired via
// `doctype_js = {"User": "public/js/user_passkeys.js"}`.
//
// Placement is DETERMINISTIC. install.sync_user_form_section adds a Custom Field
// Section Break ("passkeys_section", label "Passkeys") + an HTML wrapper
// ("passkeys_html") positioned right AFTER the User form's "Change Password" /
// security area — where a user manages their password & 2FA. This file renders into
// that HTML wrapper. When no passkey mode is active (or the app is dormant, or the
// viewer isn't allowed the section) it hides the lone HTML control, which leaves the
// section empty and Frappe collapses it (`.empty-section` → display:none). So the
// section never floats to the end of the form and never shows an empty header —
// replacing the old `frm.dashboard.add_section()` that appended non-deterministically.
//
// Own form ⇒ full interactive cards + add; another user's form (System Manager) ⇒
// read-only inventory + a link to the WebAuthn Credential DocType for admin
// disable/delete. All rendering is delegated to frappe.passkeys.manage
// (passkey_desk.bundle.js, loaded first via app_include_js); this file is only the
// form glue. Destination on core merge: the passkeys section inside
// frappe/core/doctype/user/user.js.
//
// eslint-env browser
frappe.ui.form.on("User", {
	refresh: function (frm) {
		var htmlField = frm.fields_dict && frm.fields_dict.passkeys_html;
		if (!htmlField) return; // section Custom Fields not installed ⇒ nothing to mount into

		// Collapse the section: hiding its lone HTML control makes the section empty,
		// and Frappe's layout hides an empty section (refresh_sections → .empty-section).
		function hideSection() {
			frm.toggle_display("passkeys_html", false);
			frm.refresh_field("passkeys_html");
		}

		var manage = frappe.passkeys && frappe.passkeys.manage;
		if (!manage) return hideSection(); // desk bundle not loaded (disabled site)
		if (frm.is_new()) return hideSection();

		var boot = frappe.boot && frappe.boot.passkeys;
		// Management surfaces gate on ANY passkey mode (matrix): a 2FA-only site still
		// shows them (enabled == true); both modes off — or a dormant / uninstalled app
		// (no bootinfo) — hides the section.
		if (!boot || boot.enabled === false) return hideSection();

		var isSelf = frm.doc.name === frappe.session.user;
		if (!isSelf && !frappe.user.has_role("System Manager")) return hideSection(); // no section for others

		// Show the section, then (re)render into the HTML wrapper. The HTML control has
		// no df.options, so its own refresh never clobbers our injected DOM.
		frm.toggle_display("passkeys_html", true);
		frm.refresh_field("passkeys_html");
		var host = htmlField.$wrapper && htmlField.$wrapper.get(0);
		if (!host) return;
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
					var f = frm.fields_dict && frm.fields_dict.passkeys_html;
					var w = f && f.$wrapper && f.$wrapper.get(0);
					if (!w || !w.isConnected) {
						document.removeEventListener("passkey:changed", onChange);
						return;
					}
					var r = w.querySelector(".passkey-cards-root");
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
