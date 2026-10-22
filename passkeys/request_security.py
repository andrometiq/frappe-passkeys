# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Guest request limits and identifier normalization; no crypto imports."""

from functools import wraps
from ipaddress import ip_address, ip_network

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit as core_rate_limit

from passkeys import state


def rate_limit(*, limit: int, seconds: int):
	"""Keep core's IPv4 limit and add an endpoint-scoped IPv6 /64 counter."""

	def decorate(function):
		limited = core_rate_limit(limit=limit, seconds=seconds)(function)

		@wraps(function)
		def wrapper(*args, **kwargs):
			address = getattr(frappe.local, "request_ip", None)
			if getattr(frappe.local, "request", None) and address and ":" in address:
				address = ip_address(address)
				bucket = str(address.ipv4_mapped or ip_network(f"{address}/64", strict=False))
				key = f"{state.RATE_LIMIT_PREFIX}{function.__module__}.{function.__name__}:{bucket}"
				if state.bump_counter(key, seconds) > limit:
					raise frappe.RateLimitExceededError(
						_("You've hit the rate limit. Please try again shortly.")
					)
			return limited(*args, **kwargs)

		return wrapper

	return decorate


def normalize_login_identifier(identifier: str) -> str:
	"""Email IDs are lowercase; preserve core's case-sensitive username aliases."""
	identifier = identifier.strip()
	return identifier.lower() if "@" in identifier else identifier
