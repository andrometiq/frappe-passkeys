# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Whitelisted ceremony endpoints, split per surface for the phased build.
On the core merge these fold back into a single ``frappe/passkey.py``;
the wire method paths (``passkeys.api.registration.*``) are the app-phase names.
"""
