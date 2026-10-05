"""A connector that answers with a different secret than the one asked for.

The attack the AAD does not cover. An envelope is bound to its own id and
version, so a substituted secret is internally consistent: the key CoreLink
returns for that id opens it, the version matches, the tag verifies. Every
cryptographic check passes and the application gets a value it did not ask for.

So the fixture here is a real one, produced by the platform's own crypto, served
under the wrong name. Nothing is forged -- that is the point. The only thing that
can catch it is comparing the name CoreLink says the id belongs to against the
name the application asked for.

Run: python3 -m unittest discover -s sdk/python/tests
"""

import base64
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transit_client import sealed  # noqa: E402
from transit_client.client import TransitClient  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "testdata", "sealed_envelope.json"
)

with open(FIXTURE) as fh:
    FX = json.load(fh)

# The name the fixture's secret really has, and the name the application asks
# for. The connector will answer the second with the first.
REAL_NAME = "production/other-secret"
ASKED_NAME = "production/dbone"


class _Fake(BaseHTTPRequestHandler):
    """One process standing in for both the connector and CoreLink."""

    # What the unwrap endpoint reports as the authoritative name. Set per test.
    authoritative_name = REAL_NAME

    def log_message(self, *args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # The connector: asked for one name, answers with the other secret's id
        # and envelope. A real envelope, just not the requested one.
        if self.path.startswith("/v1/envelopes/"):
            self._send(
                200,
                {
                    "secret_id": FX["secret_id"],
                    "name": ASKED_NAME,
                    "version": FX["version"],
                    "envelope": FX["envelope"],
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        # CoreLink: unwraps its own copy and says which name the id belongs to.
        if self.path.endswith("/unwrap"):
            self._send(
                200,
                {
                    "dek": FX["dek"],
                    "version": FX["version"],
                    "name": type(self).authoritative_name,
                },
            )
            return
        self._send(404, {"error": "not found"})


class TestSubstitutedSecretIsRefused(unittest.TestCase):
    def setUp(self):
        _Fake.authoritative_name = REAL_NAME
        self.srv = HTTPServer(("127.0.0.1", 0), _Fake)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.client = TransitClient(
            transit_url=base,
            platform_url=base,
            nhi_id="11111111-1111-1111-1111-111111111111",
        )
        # The session the sealed path requires; this test is about the name
        # comparison, not about how the session was obtained.
        self.client._session_id = "test-session"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_a_substituted_secret_is_refused(self):
        with self.assertRaises(sealed.WrongSecret) as caught:
            self.client.get_secret_sealed(ASKED_NAME)
        # The message has to name both, or an operator cannot tell which
        # connector lied about what.
        self.assertIn(ASKED_NAME, str(caught.exception))
        self.assertIn(REAL_NAME, str(caught.exception))

    def test_the_right_secret_still_opens(self):
        # The same path with the names agreeing: proves the check refuses
        # substitution rather than refusing everything.
        _Fake.authoritative_name = ASKED_NAME
        self.assertEqual(
            self.client.get_secret_sealed(ASKED_NAME), FX["expected_value"]
        )

    def test_no_name_from_the_platform_does_not_refuse(self):
        # An older CoreLink that does not send the name yet. Refusing here would
        # break every application against it; the AAD still binds id and version.
        _Fake.authoritative_name = ""
        self.assertEqual(
            self.client.get_secret_sealed(ASKED_NAME), FX["expected_value"]
        )


if __name__ == "__main__":
    unittest.main()
