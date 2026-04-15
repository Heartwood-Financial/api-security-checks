from __future__ import annotations

import tempfile
import unittest

from api_security_checks.envfile import load_env_file, parse_env_text


class EnvFileTests(unittest.TestCase):
    def test_parse_env_text_supports_quotes_and_export(self) -> None:
        payload = parse_env_text(
            """
            # comment
            export FOO=bar
            BAR="two words"
            BAZ='three words'
            """
        )
        self.assertEqual(payload["FOO"], "bar")
        self.assertEqual(payload["BAR"], "two words")
        self.assertEqual(payload["BAZ"], "three words")

    def test_load_env_file_does_not_override_existing_values(self) -> None:
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as handle:
            handle.write("FOO=new\nBAR=set\n")
            handle.flush()
            environ = {"FOO": "existing"}
            load_env_file(handle.name, environ=environ)
        self.assertEqual(environ["FOO"], "existing")
        self.assertEqual(environ["BAR"], "set")


if __name__ == "__main__":
    unittest.main()
