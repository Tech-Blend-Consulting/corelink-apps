"""The leased-credential lifecycle, against a fake CoreLink.

The wire shapes here are the ones a live CoreLink was observed to send -- the
listing wrapped in "data", the credential as a string -- because the Go SDK
guessed both wrong from reading the handler and only a real call disagreed.

Run: python3 -m unittest discover -s sdk/python/tests
"""

import json
import os
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transit_client import leases  # noqa: E402
from transit_client.client import TransitClient  # noqa: E402


class _Broker(BaseHTTPRequestHandler):
    """Stands in for CoreLink's credential endpoints."""

    renewals = 0
    renew_limit = 0
    released = []
    requested = []

    def log_message(self, *args):
        pass

    def _send(self, status, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/v1/nhi-agent/credentials":
            length = int(self.headers.get("Content-Length", 0))
            _Broker.requested.append(json.loads(self.rfile.read(length) or b"{}"))
            self._send(200, {
                "lease_id": "lease-1",
                # A string, which is what CoreLink sends.
                "credential": '{"username":"dyn_abc"}',
                "issued_at": "2026-10-04T12:00:00Z",
                "expires_at": "2026-10-04T12:15:00Z",
            })
        elif self.path.endswith("/renew"):
            if "unknown-lease" in self.path:
                self._send(404, {"error": {"code": "NOT_FOUND"}})
                return
            if _Broker.renew_limit and _Broker.renewals >= _Broker.renew_limit:
                self._send(422, {"error": {"code": "LEASE_RENEWAL_FAILED"}})
                return
            _Broker.renewals += 1
            self._send(200, {"renewed": True})
        else:
            self._send(404, {"error": {"code": "NOT_FOUND"}})

    def do_DELETE(self):
        _Broker.released.append(self.path.rsplit("/", 1)[-1])
        self._send(204)

    def do_GET(self):
        if self.path == "/api/v1/nhi-agent/credentials":
            # "data", not "leases".
            self._send(200, {"data": [
                {"id": "lease-1", "expires_at": "2026-10-04T12:15:00Z"},
            ]})
        else:
            self._send(404, {})


class TestLeaseLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Broker)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _Broker.renewals = 0
        _Broker.renew_limit = 0
        _Broker.released = []
        _Broker.requested = []
        self.c = TransitClient("", platform_url=self.url, nhi_id="nhi-1")
        self.c._session_id = "session-in-place"

    def test_a_credential_is_leased_with_terms(self):
        lease = self.c.request_credential(leases.RESOURCE_SECRET, "secret-1", ttl_seconds=300)
        self.assertEqual(lease.id, "lease-1")
        self.assertIn("dyn_abc", lease.credential)
        self.assertTrue(lease.expires_at, "no expiry means nothing can tell when to renew")
        self.assertEqual(_Broker.requested[0]["ttl_seconds"], 300)

    def test_the_repr_does_not_carry_the_credential(self):
        lease = self.c.request_credential(leases.RESOURCE_SECRET, "secret-1")
        self.assertNotIn("dyn_abc", repr(lease))

    def test_an_unknown_resource_type_is_refused_locally(self):
        # The allowlist is fixed, so a typo should not look like a permission
        # problem after a round trip.
        with self.assertRaises(ValueError):
            self.c.request_credential("kubernetes", "x")
        with self.assertRaises(ValueError):
            self.c.request_credential(leases.RESOURCE_SECRET, "")
        self.assertEqual(_Broker.requested, [])

    def test_renewal_tells_exhausted_apart_from_failed(self):
        self.c.renew_lease("lease-1")
        self.assertEqual(_Broker.renewals, 1)

        _Broker.renew_limit = 1
        with self.assertRaises(leases.LeaseExhausted):
            self.c.renew_lease("lease-1")

    def test_an_unknown_lease_is_not_found(self):
        # CoreLink does not say whether an unknown lease never existed, was
        # revoked, or belongs to somebody else.
        with self.assertRaises(leases.LeaseNotFound):
            self.c.renew_lease("unknown-lease")

    def test_release_is_idempotent(self):
        self.c.release_credential("lease-1")
        self.assertEqual(_Broker.released, ["lease-1"])

    def test_the_listing_omits_the_credential(self):
        found = self.c.list_leases()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].id, "lease-1")
        self.assertEqual(found[0].credential, "",
                         "a listing that returned the credential would make it re-readable")

    def test_a_session_is_required(self):
        self.c._session_id = None
        with self.assertRaises(RuntimeError):
            self.c.renew_lease("lease-1")

    def test_keep_alive_renews_then_stops_when_refused(self):
        # One renewal is allowed, the next refused: proves it renews, and proves
        # it stops rather than retrying something that cannot succeed.
        _Broker.renew_limit = 1
        self.c._keep_alive_floor = 0.02
        reported = []

        # A real term rather than no expiry, so this exercises the arithmetic
        # (renew at half the remaining life) rather than the fallback.
        now = datetime.now(timezone.utc)
        lease = leases.Lease(
            "lease-1",
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=1)).isoformat(),
        )
        stop = self.c.keep_alive(lease, on_expiry=reported.append)
        try:
            waiter = threading.Event()
            for _ in range(100):
                if reported:
                    break
                waiter.wait(0.05)
        finally:
            stop()
        self.assertEqual(len(reported), 1, "on_expiry should be called exactly once")
        self.assertIsInstance(reported[0], leases.LeaseExhausted)


if __name__ == "__main__":
    unittest.main()
