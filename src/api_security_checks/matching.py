from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlsplit


PLACEHOLDER_PATTERN = re.compile(r"{([^}]+)}")


def path_from_url(url: str) -> str:
    return urlsplit(url).path


def matches_any_pattern(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def render_probe_path(path_template: str, placeholder_uuid: str) -> str:
    def replace(match: re.Match[str]) -> str:
        raw_name = match.group(1).rstrip("?")
        lowered = raw_name.lower()
        if lowered == "version":
            return "v1"
        if lowered.endswith("id") or lowered == "id":
            return placeholder_uuid
        if "date" in lowered:
            return "2026-01-01"
        if "region" in lowered:
            return "cac"
        if "entity" in lowered:
            return "security-check"
        if "action" in lowered:
            return "version"
        return "security-check"

    return PLACEHOLDER_PATTERN.sub(replace, path_template)
