"""The sealed envelope, opened against a fixture the platform produced.

The fixture comes from internal/crypto, which is what CoreLink stores and what
the unwrap endpoint returns, so this checks agreement with the platform rather
than agreement with itself. A fake would have proved only the latter, which is
the one thing that cannot go wrong.

Regenerate the fixture with:

    go test ./internal/crypto/ -run TestSDKFixture -update

Run:

    python3 -m pytest sdk/python/tests/ -q
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transit_client import sealed  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "testdata", "sealed_envelope.json"
)


def load_fixture():
    with open(FIXTURE) as fh:
        return json.load(fh)


class TestSealedEnvelope(unittest.TestCase):
    def setUp(self):
        self.fx = load_fixture()
        self.dek = base64.b64decode(self.fx["dek"])

    def test_the_aad_matches_the_platforms(self):
        # One wire format shared with crypto.SecretAAD. If this drifts, nothing
        # opens, so it is checked against bytes the platform wrote.
        got = sealed.secret_aad(self.fx["secret_id"], self.fx["version"])
        self.assertEqual(got, base64.b64decode(self.fx["aad"]))

    def test_it_opens_what_the_platform_sealed(self):
        plaintext = sealed.open_envelope(
            self.fx["envelope"], self.dek, self.fx["secret_id"], self.fx["version"]
        )
        self.assertEqual(plaintext.decode(), self.fx["expected_plaintext"])
        self.assertEqual(sealed.value_from(plaintext), self.fx["expected_value"])

    def test_the_wrong_version_does_not_open_it(self):
        # What makes a stale cached envelope fail closed rather than being served
        # as though it were current.
        with self.assertRaises(sealed.StaleEnvelope):
            sealed.open_envelope(
                self.fx["envelope"], self.dek, self.fx["secret_id"], self.fx["version"] + 1
            )

    def test_a_false_secret_id_does_not_open_it(self):
        # The case authorization cannot catch: the caller may hold unwrap on both
        # secrets, so only the binding can stop this.
        with self.assertRaises(sealed.StaleEnvelope):
            sealed.open_envelope(
                self.fx["envelope"],
                self.dek,
                "00000000-0000-0000-0000-000000000000",
                self.fx["version"],
            )

    def test_another_key_does_not_open_it(self):
        other = bytes(32)
        with self.assertRaises(sealed.CorruptEnvelope):
            sealed.open_envelope(
                self.fx["envelope"], other, self.fx["secret_id"], self.fx["version"]
            )

    def test_altered_ciphertext_is_corrupt_not_stale(self):
        # Refetching cannot repair this, so it must not be reported as something
        # a refetch would fix.
        raw = json.loads(base64.b64decode(self.fx["envelope"]))
        data = bytearray(base64.b64decode(raw["encrypted_data"]))
        data[0] ^= 0xFF
        raw["encrypted_data"] = base64.b64encode(bytes(data)).decode()
        altered = base64.b64encode(json.dumps(raw).encode()).decode()

        with self.assertRaises(sealed.CorruptEnvelope):
            sealed.open_envelope(
                altered, self.dek, self.fx["secret_id"], self.fx["version"]
            )

    def test_envelope_path_keeps_slashes_and_refuses_dot_segments(self):
        self.assertEqual(sealed.envelope_path("production/dbone"), "production/dbone")
        self.assertEqual(sealed.envelope_path("/production/dbone/"), "production/dbone")
        self.assertEqual(sealed.envelope_path("prod/a?b"), "prod/a%3Fb")
        for bad in ["prod/../etc/passwd", "prod/.", "..", "prod//dbone", "", "/"]:
            with self.assertRaises(ValueError, msg=f"{bad!r} should be refused"):
                sealed.envelope_path(bad)


if __name__ == "__main__":
    unittest.main()


CERT_FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "testdata", "sealed_certificate.json"
)


class TestSealedCertificate(unittest.TestCase):
    """A certificate comes back one level deeper than a password.

    The stored record wraps the value, and for a certificate the value is itself
    JSON. An SDK that returned the record rather than its value would look
    correct on a password and produce an empty certificate here, so this runs
    the whole local chain against a bundle the platform sealed.
    """

    def setUp(self):
        with open(CERT_FIXTURE) as fh:
            self.fx = json.load(fh)
        self.dek = base64.b64decode(self.fx["dek"])

    def test_the_chain_produces_the_bundle_the_platform_sealed(self):
        plaintext = sealed.open_envelope(
            self.fx["envelope"], self.dek, self.fx["secret_id"], self.fx["version"]
        )
        value = sealed.value_from(plaintext)
        self.assertEqual(value, self.fx["expected_value"])

        cert = sealed.certificate_from(value)
        self.assertIn("BEGIN CERTIFICATE", cert.certificate)
        self.assertIn("BEGIN PRIVATE KEY", cert.private_key)
        self.assertIn("BEGIN CERTIFICATE", cert.ca_chain)

    def test_a_secret_that_is_not_a_bundle_is_refused(self):
        # An empty Certificate returned as success would fail later and
        # somewhere else.
        for bad in ['{"value":"a-password"}', "a-bare-password", "{}",
                    '{"certificate":"c"}', '{"private_key":"k"}', "[]"]:
            with self.assertRaises(ValueError, msg=f"{bad!r} should be refused"):
                sealed.certificate_from(bad)

    def test_the_repr_does_not_carry_the_key(self):
        cert = sealed.Certificate("cert-pem", "super-secret-key")
        self.assertNotIn("super-secret-key", repr(cert))


class TestAPreBindingEnvelopeOpens(unittest.TestCase):
    """An envelope written before binding existed carries no AAD, and opens.

    Not a rollback -- the thing this must never be confused with. The platform
    skips its own compare for these, so an SDK that insisted on the expected AAD
    would call every pre-binding secret corrupt. All twenty of production's
    versions were unbound when this was measured, so that SDK could not read a
    single real secret.
    """

    def setUp(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "testdata", "sealed_legacy_no_aad.json"
        )
        with open(path) as fh:
            self.fx = json.load(fh)

    def test_it_opens_and_is_not_called_corrupt(self):
        plaintext = sealed.open_envelope(
            self.fx["envelope"],
            base64.b64decode(self.fx["dek"]),
            self.fx["secret_id"],
            self.fx["version"],
        )
        self.assertEqual(sealed.value_from(plaintext), self.fx["expected_value"])

    def test_a_wrong_key_is_still_refused(self):
        # Unbound does not mean unchecked: the key still has to be the right one.
        with self.assertRaises(sealed.CorruptEnvelope):
            sealed.open_envelope(
                self.fx["envelope"], b"\x00" * 32, self.fx["secret_id"], self.fx["version"]
            )
