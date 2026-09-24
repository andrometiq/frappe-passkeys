// The "Passkeys" section on the Desk User form, rendered into the passkeys_html Custom
// Field (install.sync_user_form_section). Own form: interactive cards; another user's
// (System Manager): a read-only inventory plus enforcement recovery.
// eslint-env browser
frappe.ui.form.on("User", {
	refresh: function (frm) {
		var htmlField = frm.fields_dict.passkeys_html;
		if (!htmlField) return; // the section's Custom Fields are not installed

		// Hiding the section's only control makes Frappe collapse the empty section.
		function hideSection() {
			frm.toggle_display("passkeys_html", false);
			frm.refresh_field("passkeys_html");
		}

		var manage = frappe.passkeys.manage;
		var boot = frappe.boot.passkeys;
		// Both modes off, or a dormant app (no boot payload): no section.
		if (frm.is_new() || !manage || !boot || boot.enabled === false) return hideSection();

		var isSelf = frm.doc.name === frappe.session.user;
		if (!isSelf && !frappe.user.has_role("System Manager")) return hideSection();

		// The HTML control has no df.options, so its own refresh never clobbers this DOM.
		frm.toggle_display("passkeys_html", true);
		frm.refresh_field("passkeys_html");
		var host = htmlField.$wrapper.get(0);
		host.innerHTML = "";

		var root = document.createElement("div");
		if (isSelf) {
			root.className = "passkey-cards-root";
			host.appendChild(root);
			manage.renderCards(root, { root: root });
			if (!frm._passkey_change_bound) {
				frm._passkey_change_bound = true;
				// Keep the section fresh after an add / rename / delete elsewhere.
				document.addEventListener("passkey:changed", function onChange() {
					var wrapper = frm.fields_dict.passkeys_html.$wrapper.get(0);
					if (!wrapper.isConnected) {
						document.removeEventListener("passkey:changed", onChange);
						return;
					}
					var cards = wrapper.querySelector(".passkey-cards-root");
					if (cards) manage.renderCards(cards, { root: cards });
				});
			}
		} else {
			root.className = "passkey-admin-inventory";
			host.appendChild(root);
			manage.renderReadOnlyInventory(root, frm.doc.name);
			var enforcementRoot = document.createElement("div");
			enforcementRoot.className = "passkey-admin-enforcement";
			host.appendChild(enforcementRoot);
			manage.renderEnforcementAdmin(enforcementRoot, frm.doc.name, boot);
		}
	},
});
