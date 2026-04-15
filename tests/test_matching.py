from __future__ import annotations

import unittest

from api_security_checks.matching import matches_any_pattern, render_probe_path


class MatchingTests(unittest.TestCase):
    def test_matches_frontdoor_style_patterns(self) -> None:
        self.assertTrue(matches_any_pattern("/api/helpdesk/tickets", ["/api/helpdesk/*"]))
        self.assertTrue(matches_any_pattern("/api/helpdesk", ["/api/helpdesk"]))
        self.assertFalse(matches_any_pattern("/api/helpdesk/tickets", ["/api/link-lender/*"]))

    def test_render_probe_path_substitutes_placeholders(self) -> None:
        path = render_probe_path(
            "/api/helpdesk/tickets/{ticketid}/attachments/{attachmentid}",
            "00000000-0000-0000-0000-000000000000",
        )
        self.assertEqual(
            path,
            "/api/helpdesk/tickets/00000000-0000-0000-0000-000000000000/attachments/00000000-0000-0000-0000-000000000000",
        )

    def test_render_probe_path_uses_v1_for_version_placeholder(self) -> None:
        path = render_probe_path("/api/tool/{version}/status", "ignored")
        self.assertEqual(path, "/api/tool/v1/status")


if __name__ == "__main__":
    unittest.main()
