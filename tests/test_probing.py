from __future__ import annotations

import unittest

from api_security_checks.models import Endpoint, ProbeProfile, ScanSettings
from api_security_checks.probing import _classify


class ProbingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = Endpoint(
            surface_name="test",
            environment="dev",
            kind="direct",
            function_app="func-test",
            resource_group="rg-test",
            function_name="func-test/version",
            method="GET",
            path_template="/api/test/version",
            probe_path="/api/test/version",
            probe_url="https://example.com/api/test/version",
            auth_level="anonymous",
            invoke_url_template="https://example.com/api/test/version",
        )
        self.scan = ScanSettings(
            title="Test",
            wrong_audience_token_command="echo token",
        )

    def test_anonymous_200_is_exposed(self) -> None:
        profile = ProbeProfile(name="anonymous", description="anon")
        self.assertEqual(_classify(200, self.endpoint, profile), "exposed")

    def test_wrong_audience_401_is_denied(self) -> None:
        profile = ProbeProfile(name="wrong_audience", description="graph")
        self.assertEqual(_classify(401, self.endpoint, profile), "denied")

    def test_anonymous_400_is_potential_bypass(self) -> None:
        profile = ProbeProfile(name="anonymous", description="anon")
        self.assertEqual(_classify(400, self.endpoint, profile), "potential_auth_bypass")

    def test_valid_token_200_is_authorized(self) -> None:
        profile = ProbeProfile(name="valid_token", description="valid")
        self.assertEqual(_classify(200, self.endpoint, profile), "authorized")


if __name__ == "__main__":
    unittest.main()
