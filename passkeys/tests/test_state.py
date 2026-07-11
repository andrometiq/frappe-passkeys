# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""P1 battery: challenge/state store — single-use
atomic consume (incl. the two-connection race), TTL honesty, JSON-not-pickle,
fail-closed on miss, the counter idiom, and the request-local staleness pin
that keeps the wrapper banned for single-use keys."""

import json
import threading
import time

import frappe
import redis

from passkeys import state
from passkeys.tests.compat import IntegrationTestCase


def raw_connection() -> redis.Redis:
	"""An independent raw connection — deliberately NOT frappe.cache."""
	return redis.Redis.from_url(frappe.local.conf.get("redis_cache"))


class TestStateStore(IntegrationTestCase):
	def test_store_and_consume_round_trip(self):
		record = {"v": 1, "type": "login", "challenge_b64": "abc", "origins": ["https://x.example"]}
		state_id = state.store_ceremony(record)

		self.assertEqual(state.consume_ceremony(state_id), record)

	def test_consume_is_single_use(self):
		state_id = state.store_ceremony({"type": "login"})

		self.assertIsNotNone(state.consume_ceremony(state_id))
		self.assertIsNone(state.consume_ceremony(state_id))

	def test_consume_fails_closed_on_unknown_id(self):
		self.assertIsNone(state.consume_ceremony(frappe.generate_hash()))

	def test_ttl_is_set_at_write_and_honored(self):
		state_id = state.store_ceremony({"type": "login"}, ttl=1)
		key = frappe.cache.make_key(state.CEREMONY_PREFIX + state_id)

		pttl = frappe.cache.pttl(key)
		self.assertGreater(pttl, 0)
		self.assertLessEqual(pttl, 1000)

		time.sleep(1.2)
		self.assertIsNone(state.consume_ceremony(state_id))

	def test_values_are_json_not_pickle(self):
		record = {"type": "login", "user": "someone@example.com"}
		state_id = state.store_ceremony(record)
		key = frappe.cache.make_key(state.CEREMONY_PREFIX + state_id)

		raw = raw_connection().get(key)
		self.assertTrue(raw.startswith(b"{"))
		self.assertEqual(json.loads(raw), record)

		state.consume_ceremony(state_id)

	def test_getdel_race_exactly_one_winner(self):
		"""Regression pin: two raw connections race the consume; exactly
		one wins on every round (bench-proven 200/200 in PROBE-bench)."""
		clients = (raw_connection(), raw_connection())
		for _ in range(50):
			state_id = state.store_ceremony({"type": "login"})
			key = frappe.cache.make_key(state.CEREMONY_PREFIX + state_id)
			barrier = threading.Barrier(2)
			results = []

			def consume(client, key=key, barrier=barrier, results=results):
				barrier.wait()
				results.append(client.getdel(key))

			threads = [threading.Thread(target=consume, args=(client,)) for client in clients]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join()

			winners = [value for value in results if value is not None]
			self.assertEqual(len(winners), 1)

	def test_pipeline_fallback_race_exactly_one_winner(self):
		"""The documented Redis < 6.2 MULTI/EXEC fallback: proceed iff the value
		was present AND this caller's DELETE removed it (delete count == 1)."""
		clients = (raw_connection(), raw_connection())
		for _ in range(50):
			state_id = state.store_ceremony({"type": "login"})
			key = frappe.cache.make_key(state.CEREMONY_PREFIX + state_id)
			barrier = threading.Barrier(2)
			results = []

			def consume(client, key=key, barrier=barrier, results=results):
				barrier.wait()
				pipe = client.pipeline()
				pipe.get(key)
				pipe.delete(key)
				raw, deleted = pipe.execute()
				results.append(raw if (raw is not None and deleted) else None)

			threads = [threading.Thread(target=consume, args=(client,)) for client in clients]
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join()

			winners = [value for value in results if value is not None]
			self.assertEqual(len(winners), 1)

	def test_pipeline_fallback_single_caller_semantics(self):
		state_id = state.store_ceremony({"type": "login"})
		key = frappe.cache.make_key(state.CEREMONY_PREFIX + state_id)

		raw = state._consume_via_pipeline(key)
		self.assertIsNotNone(raw)
		self.assertEqual(json.loads(raw), {"type": "login"})
		self.assertIsNone(state._consume_via_pipeline(key))

	def test_wrapper_get_value_serves_stale_local_copy(self):
		"""Pin: the RedisWrapper request-local cache is provably
		stale after a remote delete — the reason wrapper ``*_value`` methods
		stay banned for single-use keys. If this test ever fails, the wrapper
		semantics changed; re-evaluate before touching state.py."""
		key_name = f"passkeys:test:stale-{frappe.generate_hash(length=8)}"
		frappe.cache.set_value(key_name, "v1")
		self.assertEqual(frappe.cache.get_value(key_name), "v1")

		raw_connection().delete(frappe.cache.make_key(key_name))

		self.assertEqual(frappe.cache.get_value(key_name), "v1")  # stale!
		frappe.local.cache.pop(frappe.cache.make_key(key_name), None)

	def test_get_value_expires_true_is_not_a_local_cache_bypass(self):
		"""Pin: ``get_value(expires=True)`` is NOT a fresh-read escape
		hatch. In ``redis_wrapper.py`` the request-local-cache hit is checked BEFORE
		the ``expires`` branch, so a key already resident in ``frappe.local.cache``
		serves the STALE copy even with ``expires=True`` — only ``expires`` controls
		whether a *fresh* read is re-stored locally, never whether the local copy is
		consulted. This guards against a future "simplification" that reintroduces the
		wrapper for single-use keys under the belief ``expires=True`` reads live Redis.
		The complement — state.py's raw ``.get()`` honours real Redis state — is
		pinned in the second half."""
		key_name = f"passkeys:test:exp-{frappe.generate_hash(length=8)}"
		made = frappe.cache.make_key(key_name)
		# populate BOTH Redis and the request-local cache (set_value does both)
		frappe.cache.set_value(key_name, "v1")
		self.assertEqual(frappe.cache.get_value(key_name, expires=True), "v1")

		# another worker consumes/expires the key — it is physically gone from Redis
		raw_connection().delete(made)
		self.assertIsNone(raw_connection().get(made))

		# ...yet get_value(expires=True) STILL returns the stale local copy: the
		# local-cache branch precedes the expires branch. NOT a bypass.
		self.assertEqual(frappe.cache.get_value(key_name, expires=True), "v1")
		frappe.local.cache.pop(made, None)

		# state.py's raw idiom is the only correct read: set_sudo_window/get_sudo_window
		# never touch frappe.local.cache, so a remote delete reads back None (real TTL
		# / consume state honoured), where the wrapper above lied.
		sid = frappe.generate_hash()
		state.set_sudo_window(sid, {"v": 1, "user": "x", "seeded_by": "password"}, ttl=60)
		self.assertIsNotNone(state.get_sudo_window(sid))
		raw_connection().delete(frappe.cache.make_key(state.SUDO_PREFIX + sid))
		self.assertIsNone(state.get_sudo_window(sid))

	def test_counter_idiom_ttl_at_creation(self):
		name = f"passkeys:pwfail:test-{frappe.generate_hash(length=8)}"
		self.addCleanup(state.clear_counter, name)

		self.assertEqual(state.bump_counter(name, ttl=60), 1)
		self.assertGreater(frappe.cache.pttl(frappe.cache.make_key(name)), 0)
		self.assertEqual(state.bump_counter(name, ttl=60), 2)
		self.assertEqual(state.bump_counter(name, ttl=60), 3)
		self.assertEqual(state.get_counter(name), 3)

		state.clear_counter(name)
		self.assertEqual(state.get_counter(name), 0)

	def test_counter_expires(self):
		name = f"passkeys:pwfail:test-{frappe.generate_hash(length=8)}"
		self.addCleanup(state.clear_counter, name)

		state.bump_counter(name, ttl=1)
		time.sleep(1.2)
		self.assertEqual(state.get_counter(name), 0)
		self.assertEqual(state.bump_counter(name, ttl=60), 1)

	def test_password_failure_throttle(self):
		user = f"throttle-{frappe.generate_hash(length=8)}@example.com"
		self.addCleanup(state.clear_password_failures, user)

		for attempt in range(1, state.PASSWORD_FAILURE_LIMIT):
			state.record_password_failure(user)
			self.assertFalse(state.is_password_throttled(user), attempt)
		state.record_password_failure(user)
		self.assertTrue(state.is_password_throttled(user))

		state.clear_password_failures(user)
		self.assertFalse(state.is_password_throttled(user))

	def test_sudo_window_round_trip(self):
		sid = frappe.generate_hash()
		record = {"user": "someone@example.com", "seeded_by": "password"}

		state.set_sudo_window(sid, record, ttl=60)
		self.assertEqual(state.get_sudo_window(sid), record)

		state.clear_sudo_window(sid)
		self.assertIsNone(state.get_sudo_window(sid))
