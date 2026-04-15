from __future__ import annotations

import tomllib
from pathlib import Path

from .models import FrontDoorDefaults, Manifest, ScanSettings, SurfaceConfig


def load_manifest(path: str | Path) -> Manifest:
    manifest_path = Path(path)
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))

    scan_block = data.get("scan", {})
    frontdoor_block = data.get("frontdoor_defaults")
    surface_blocks = data.get("surfaces", [])

    scan = ScanSettings(
        title=scan_block.get("title", "API Security Checks"),
        wrong_audience_token_command=scan_block["wrong_audience_token_command"],
        exempt_path_patterns=list(scan_block.get("exempt_path_patterns", [])),
        request_timeout_seconds=int(scan_block.get("request_timeout_seconds", 20)),
        placeholder_uuid=scan_block.get("placeholder_uuid", "00000000-0000-0000-0000-000000000000"),
        malformed_json_body=scan_block.get("malformed_json_body", '{"probe":'),
    )

    frontdoor_defaults = None
    if frontdoor_block:
        frontdoor_defaults = FrontDoorDefaults(
            resource_group=frontdoor_block["resource_group"],
            profile_name=frontdoor_block["profile_name"],
            endpoint_name=frontdoor_block["endpoint_name"],
            base_url=frontdoor_block["base_url"],
        )

    surfaces = [
        SurfaceConfig(
            name=surface["name"],
            environment=surface["environment"],
            kind=surface["kind"],
            resource_group=surface["resource_group"],
            function_app=surface["function_app"],
            base_url=surface.get("base_url"),
            route_names=list(surface.get("route_names", [])),
            notes=surface.get("notes"),
            valid_token_command=surface.get("valid_token_command"),
            valid_token_mode=surface.get("valid_token_mode"),
        )
        for surface in surface_blocks
    ]

    if not surfaces:
        raise ValueError(f"No surfaces were defined in {manifest_path}")

    return Manifest(scan=scan, frontdoor_defaults=frontdoor_defaults, surfaces=surfaces)
