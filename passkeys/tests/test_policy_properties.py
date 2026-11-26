# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Property tests for the pure RP-scope, origin and authenticator-counter rules in
``passkeys.policy``. Hypothesis comes with Frappe's dev dependencies
(``bench setup requirements --dev``)."""

import re
import string
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import frappe
from hypothesis import example, given, settings
from hypothesis import strategies as st

from passkeys import policy

PROPERTY = settings(max_examples=100, deadline=None, database=None)
DEFAULT_PORTS = {"http": 80, "https": 443}
BASE64URL = string.ascii_letters + string.digits + "-_"
APP_ORIGIN = re.compile(r"android:apk-key-hash:[A-Za-z0-9_-]{43}")

# ASCII host names: a non-ASCII host goes through IDNA, which these oracles do not model.
LABEL = st.text(alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=12)
HOST = st.lists(LABEL, min_size=1, max_size=4).map(".".join)
RP_ID = HOST.map(str.lower)
PORT = st.none() | st.integers(min_value=1, max_value=65535)
LOOSE_ORIGIN = st.tuples(
	st.sampled_from(["https://", "HTTP://", "http://", "https:", "ftp://", "//", ""]),
	st.sampled_from(["", "user@", "user:secret@", ":@", "@"]),
	st.text(alphabet=st.characters(max_codepoint=127), max_size=16),
	st.sampled_from(["", ":", ":0", ":80", ":443", ":8443", ":65536", ":-1", ":x"]),
	st.sampled_from(["", "/", "/path", "?", "?q=1", "#", "#top", "\\"]),
).map("".join)
APP_ORIGIN_LIKE = st.tuples(
	st.sampled_from(["android:apk-key-hash:", "ANDROID:apk-key-hash:", "android:apk-key-hash", "ios:", ""]),
	st.text(alphabet=BASE64URL, min_size=42, max_size=44)
	| st.text(alphabet=BASE64URL + "=+/. ", min_size=43, max_size=43),
).map("".join)
COUNTER = st.integers(min_value=0, max_value=2**32 - 1)
FLAG = st.booleans() | st.sampled_from([0, 1])


def with_port(host: str, port: int | None) -> str:
	return host if port is None else f"{host}:{port}"


@st.composite
def host_in_scope(draw):
	"""A mixed-case host and the lower-case RP ID it equals or is a subdomain of."""
	labels = draw(st.lists(LABEL, min_size=1, max_size=4))
	cut = draw(st.integers(min_value=0, max_value=len(labels) - 1))
	return ".".join(labels), ".".join(labels[cut:]).lower()


@st.composite
def counter_pair(draw):
	"""A stored and an asserted sign count, often equal, adjacent or zero."""
	stored = draw(COUNTER)
	asserted = draw(COUNTER | st.sampled_from([0, stored, stored + 1, max(stored - 1, 0)]))
	return stored, asserted


class CanonicalWebOriginPropertiesTest(unittest.TestCase):
	@PROPERTY
	@given(st.text() | LOOSE_ORIGIN)
	def test_a_canonical_origin_is_a_bare_lower_case_fixed_point(self, raw):
		canonical = policy.canonical_web_origin(raw)
		if canonical is None:
			return
		parts = urlsplit(canonical)
		self.assertEqual(policy.canonical_web_origin(canonical), canonical)
		self.assertEqual(canonical, canonical.lower())
		self.assertEqual(
			(parts.username, parts.password, parts.path, parts.query, parts.fragment),
			(None, None, "", "", ""),
		)
		self.assertNotEqual(parts.port, DEFAULT_PORTS[parts.scheme])

	@PROPERTY
	@given(
		scheme=st.sampled_from(["http", "https", "HTTP", "Https", "ftp", "wss"]),
		userinfo=st.sampled_from(["", "user@", "user:secret@", ":secret@"]),
		host=HOST,
		port=PORT,
		tail=st.sampled_from(["", "/", "/path", "/a/b/", "?next=/", "#top"]),
	)
	@example(scheme="HTTPS", userinfo="", host="Login.Example.COM", port=443, tail="")
	@example(scheme="http", userinfo="", host="LOCALHOST", port=80, tail="")
	@example(scheme="https", userinfo="", host="example.com", port=None, tail="/")
	def test_a_canonical_origin_is_the_scheme_host_and_any_non_default_port(
		self, scheme, userinfo, host, port, tail
	):
		canonical = policy.canonical_web_origin(f"{scheme}://{userinfo}{with_port(host, port)}{tail}")
		scheme = scheme.lower()
		if scheme not in DEFAULT_PORTS or userinfo or tail:
			self.assertIsNone(canonical)
		else:
			kept_port = None if port == DEFAULT_PORTS[scheme] else port
			self.assertEqual(canonical, f"{scheme}://{with_port(host.lower(), kept_port)}")


class RpScopePropertiesTest(unittest.TestCase):
	@PROPERTY
	@given(host_in_scope())
	def test_the_rp_id_and_its_subdomains_are_in_scope(self, scope):
		host, rp_id = scope
		self.assertTrue(policy.is_in_rp_scope(host.lower(), rp_id))

	@PROPERTY
	@given(rp_id=RP_ID, prefix=st.text(min_size=1).filter(lambda prefix: not prefix.endswith(".")))
	@example(rp_id="example.com", prefix="evil")
	@example(rp_id="example.com", prefix="evil-")
	def test_a_host_that_only_ends_with_the_rp_id_is_out_of_scope(self, rp_id, prefix):
		self.assertFalse(policy.is_in_rp_scope(prefix + rp_id, rp_id))

	@PROPERTY
	@given(rp_id=RP_ID, child=LABEL)
	def test_a_parent_domain_is_out_of_scope_of_a_subdomain_rp_id(self, rp_id, child):
		self.assertFalse(policy.is_in_rp_scope(rp_id, f"{child.lower()}.{rp_id}"))

	@PROPERTY
	@given(host_in_scope())
	def test_scope_compares_case_exactly_and_origin_checks_lower_the_host(self, scope):
		host, rp_id = scope
		if rp_id != rp_id.upper():
			self.assertFalse(policy.is_in_rp_scope(host.upper(), rp_id))
		self.assertIsNone(policy.origin_error(f"https://{host.upper()}", rp_id))


class OriginErrorPropertiesTest(unittest.TestCase):
	@PROPERTY
	@given(scope=host_in_scope(), port=PORT, developer_mode=st.booleans())
	def test_an_https_origin_in_rp_scope_has_no_error(self, scope, port, developer_mode):
		host, rp_id = scope
		origin = f"https://{with_port(host, port)}"
		with patch.dict(frappe.conf, {"developer_mode": developer_mode}):
			self.assertIsNone(policy.origin_error(origin, rp_id))
			self.assertIsNone(policy.origin_error(origin, None))

	@PROPERTY
	@given(
		host=HOST | st.sampled_from(["localhost", "LocalHost", "127.0.0.1"]),
		port=PORT,
		rp_id=st.none() | RP_ID | st.just("localhost"),
		developer_mode=st.booleans(),
	)
	def test_http_is_refused_outside_the_developer_localhost_exception(
		self, host, port, rp_id, developer_mode
	):
		with patch.dict(frappe.conf, {"developer_mode": developer_mode}):
			error = policy.origin_error(f"http://{with_port(host, port)}", rp_id)
		exempt = developer_mode and host.lower() in policy.LOCALHOST_HOSTS
		in_scope = rp_id is None or policy.is_in_rp_scope(host.lower(), rp_id)
		self.assertEqual(error is None, exempt and in_scope)

	@PROPERTY
	@given(origin=st.text() | LOOSE_ORIGIN, rp_id=st.none() | RP_ID, developer_mode=st.booleans())
	def test_a_malformed_origin_gets_an_error_message_never_an_exception(self, origin, rp_id, developer_mode):
		with patch.dict(frappe.conf, {"developer_mode": developer_mode}):
			error = policy.origin_error(origin, rp_id)
		self.assertTrue(error is None or (isinstance(error, str) and error))
		if policy.canonical_web_origin(origin) is None:
			self.assertIsNotNone(error)

	@PROPERTY
	@given(st.text() | APP_ORIGIN_LIKE)
	@example("android:apk-key-hash:" + "a" * 43)
	def test_only_the_exact_apk_key_hash_form_is_a_trusted_app_origin(self, raw):
		error = policy.app_origin_error(raw)
		self.assertTrue(error is None or (isinstance(error, str) and error))
		origin = raw.strip()  # app_origins() hands every line over trimmed
		self.assertEqual(policy.app_origin_error(origin) is None, APP_ORIGIN.fullmatch(origin) is not None)


class AuthenticatorCounterPropertiesTest(unittest.TestCase):
	@PROPERTY
	@given(counter_pair())
	@example((0, 0))
	@example((7, 7))
	@example((7, 0))
	def test_sign_counts_are_classified_by_the_documented_rules(self, pair):
		stored, asserted = pair
		classified = policy.classify_sign_count(stored, asserted)
		if asserted < stored:
			self.assertEqual(classified, policy.SIGN_COUNT_REGRESSION)
		elif asserted > stored:
			self.assertEqual(classified, policy.SIGN_COUNT_INCREMENT)
		elif stored:
			self.assertEqual(classified, policy.SIGN_COUNT_REPLAY)
		else:  # an authenticator without a counter always asserts 0
			self.assertEqual(classified, policy.SIGN_COUNT_UNCHANGED)

	@PROPERTY
	@given(start=COUNTER, asserted=st.lists(COUNTER | st.just(0), max_size=20))
	def test_the_stored_sign_count_never_decreases(self, start, asserted):
		stored = start
		for value in asserted:
			stored_next = policy.sign_count_to_store(stored, value)
			self.assertEqual(stored_next, max(stored, value))
			stored = stored_next
		self.assertEqual(stored, max([start, *asserted]))

	@PROPERTY
	@given(stored=FLAG, asserted=FLAG)
	def test_backup_eligibility_is_mutated_exactly_when_the_flag_changes(self, stored, asserted):
		self.assertEqual(policy.backup_eligibility_mutated(stored, asserted), bool(stored) != bool(asserted))

	@PROPERTY
	@given(uv_bit=st.booleans(), uv_initialized=st.booleans())
	def test_only_a_verified_user_on_an_initialized_credential_gets_a_session(self, uv_bit, uv_initialized):
		outcome = policy.passwordless_uv_outcome(uv_bit, uv_initialized)
		if not uv_bit:
			self.assertEqual(outcome, policy.UV_REJECT)
		else:
			self.assertEqual(outcome, policy.UV_SESSION if uv_initialized else policy.UV_SETUP)
