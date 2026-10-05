"""The deployment file reader, against the cases every SDK shares.

Six hand-written readers drift unless one thing pins them.
``sdk/testdata/deployment_cases.json`` is that thing: the accepted files with
their expected result, and the rejected files that must be refused rather than
read as something their author did not write.

Run: python3 -m unittest discover -s sdk/python/tests
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transit_client import deployment  # noqa: E402

CASES = os.path.join(
    os.path.dirname(__file__), "..", "..", "testdata", "deployment_cases.json"
)


def load_cases():
    with open(CASES) as fh:
        return json.load(fh)


def parse_text(text):
    """Run the whole load, so the shared cases exercise what an application calls."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "secrets.yaml")
        with open(p, "w") as fh:
            fh.write(text)
        return deployment.load_deployment(p)


class TestTheSharedDeploymentCases(unittest.TestCase):
    def setUp(self):
        self.cases = load_cases()
        self.assertTrue(self.cases["accepted"])
        self.assertTrue(self.cases["rejected"])

    def test_accepted(self):
        for case in self.cases["accepted"]:
            with self.subTest(case["name"]):
                d = parse_text(case["text"])
                self.assertEqual(d.nhi_id, case["nhiId"])
                self.assertEqual(d.service_account, case["serviceAccount"])
                self.assertEqual(d.secrets, case["secrets"])

    def test_rejected(self):
        for case in self.cases["rejected"]:
            with self.subTest(case["name"]):
                with self.assertRaises(
                    deployment.DeploymentError,
                    msg=f"{case['name']} was accepted; it should be refused rather than "
                    "read as something its author did not write",
                ):
                    parse_text(case["text"])


class TestLoading(unittest.TestCase):
    def test_a_missing_file_is_not_an_error_for_the_optional_loader(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "absent.yaml")
            self.assertIsNone(deployment.load_deployment_if_present(missing))

    def test_but_a_file_that_does_not_parse_still_is(self):
        # "No file" and "a file I could not read" are different, and running the
        # application on a configuration nobody wrote is the wrong recovery.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "broken.yaml")
            with open(p, "w") as fh:
                fh.write("nhiId: a\nsecrets: [one]\n")
            with self.assertRaises(deployment.DeploymentError):
                deployment.load_deployment_if_present(p)

    def test_the_environment_overrides_the_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "elsewhere.yaml")
            with open(p, "w") as fh:
                fh.write("nhiId: abc\nsecrets: production/one\n")
            os.environ[deployment.DEPLOYMENT_PATH_ENV] = p
            try:
                self.assertEqual(deployment.load_deployment().path, p)
            finally:
                del os.environ[deployment.DEPLOYMENT_PATH_ENV]


class TestTheServiceAccountCheck(unittest.TestCase):
    def test_no_name_means_no_opinion(self):
        deployment.Deployment(nhi_id="a", secrets=["one"]).verify_service_account()

    def test_no_token_means_no_opinion(self):
        # Not running under Kubernetes, which is the ordinary case for a host.
        deployment.Deployment(
            nhi_id="a", service_account="orders", secrets=["one"]
        ).verify_service_account()

    def test_it_reads_the_name_out_of_a_projected_token(self):
        import base64

        payload = json.dumps(
            {
                "kubernetes.io": {"serviceaccount": {"name": "orders"}},
                "sub": "system:serviceaccount:prod:orders",
            }
        ).encode()
        token = "x." + base64.urlsafe_b64encode(payload).decode().rstrip("=") + ".y"
        self.assertEqual(deployment._service_account_from_token(token), "orders")

    def test_it_falls_back_to_the_subject(self):
        import base64

        payload = json.dumps({"sub": "system:serviceaccount:prod:billing"}).encode()
        token = "x." + base64.urlsafe_b64encode(payload).decode().rstrip("=") + ".y"
        self.assertEqual(deployment._service_account_from_token(token), "billing")

    def test_junk_is_no_opinion(self):
        self.assertIsNone(deployment._service_account_from_token("not-a-token"))


if __name__ == "__main__":
    unittest.main()
