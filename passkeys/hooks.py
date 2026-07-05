app_name = "passkeys"
app_title = "Passkeys"
app_publisher = "Frappe Passkeys Contributors"
app_description = "Passkey (WebAuthn) authentication for Frappe"
app_email = "passkeys@example.com"
app_license = "MIT"

# Installation
# ------------
# Version floor + fresh-install-onto-native-core refusal (DESIGN-v1 §14): the
# before_install placement is load-bearing — an after_install raise would leave
# a half-installed, registered app.
before_install = ["passkeys.install.before_install"]
after_install = ["passkeys.install.after_install"]

# Uninstallation
# --------------
before_uninstall = ["passkeys.install.before_uninstall"]

# Migration
# ---------
# Programmatic registry Property Setter — never a fixtures/ fixture (§14).
after_migrate = ["passkeys.install.sync_registry_fixture"]

# Document Events
# ---------------
doc_events = {
	"User": {
		# Without this cascade, Link integrity blocks User deletion (§2.2).
		"on_trash": "passkeys.passkey.cascade_delete_user_artifacts",
	},
}
