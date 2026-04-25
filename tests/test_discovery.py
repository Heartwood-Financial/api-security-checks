from __future__ import annotations

import unittest
from unittest import mock

from api_security_checks.discovery import discover_direct_functionapp_surfaces, infer_environment
from api_security_checks.models import SurfaceConfig


class DirectDiscoveryTests(unittest.TestCase):
    def test_infer_environment_from_resource_name(self) -> None:
        self.assertEqual(infer_environment("rg-accounting-api-dev-cae", "func-accounting-api-dev-cae"), "dev")
        self.assertEqual(infer_environment("rg-tools-api-prod-cac", "func-helpdesk-api-prod-cac"), "prod")
        self.assertEqual(infer_environment("HeartwoodData", "newton-data-sync-uat"), "uat")

    def test_discover_direct_functionapp_surfaces_skips_existing_and_stopped(self) -> None:
        existing = [
            SurfaceConfig(
                name="existing",
                environment="prod",
                kind="direct",
                resource_group="rg-prod",
                function_app="func-existing-prod-cac",
                base_url="https://func-existing-prod-cac.azurewebsites.net",
            )
        ]
        apps = [
            {
                "name": "func-existing-prod-cac",
                "resourceGroup": "rg-prod",
                "defaultHostName": "func-existing-prod-cac.azurewebsites.net",
                "state": "Running",
            },
            {
                "name": "func-new-dev-cae",
                "resourceGroup": "rg-new-dev-cae",
                "defaultHostName": "func-new-dev-cae.azurewebsites.net",
                "state": "Running",
            },
            {
                "name": "func-stopped-dev-cae",
                "resourceGroup": "rg-new-dev-cae",
                "defaultHostName": "func-stopped-dev-cae.azurewebsites.net",
                "state": "Stopped",
            },
        ]

        with mock.patch("api_security_checks.azure.list_function_apps", return_value=apps):
            surfaces = discover_direct_functionapp_surfaces(existing, states={"Running"})

        self.assertEqual([surface.function_app for surface in surfaces], ["func-new-dev-cae"])
        self.assertEqual(surfaces[0].base_url, "https://func-new-dev-cae.azurewebsites.net")
        self.assertEqual(surfaces[0].valid_token_mode, "appsetting")


if __name__ == "__main__":
    unittest.main()
