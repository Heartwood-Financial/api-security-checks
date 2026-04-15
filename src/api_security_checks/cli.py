from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from . import azure
from .config import load_manifest
from .discovery import discover_surface_endpoints
from .models import EndpointReport, SurfaceReport, to_plain_dict
from .probing import build_probe_profiles, probe_endpoint
from .report import is_exempt, render_markdown, write_inventory, write_json_report, write_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover and probe Azure API surfaces.")
    parser.add_argument(
        "--config",
        default="config/heartwood.toml",
        help="Path to the TOML manifest that defines scanned surfaces.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for generated reports. Defaults to output/<timestamp>.",
    )
    parser.add_argument(
        "--surface",
        action="append",
        default=[],
        help="Optional surface name filter. Repeat to include multiple surfaces.",
    )
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("output") / stamp


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    manifest = load_manifest(args.config)
    selected = {name for name in args.surface}
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    surface_reports: list[SurfaceReport] = []

    for surface in manifest.surfaces:
        if selected and surface.name not in selected:
            continue

        print(f"[discover] {surface.name}")
        endpoints, route_patterns = discover_surface_endpoints(
            surface,
            placeholder_uuid=manifest.scan.placeholder_uuid,
            frontdoor_defaults=manifest.frontdoor_defaults,
        )
        restrictions = azure.get_access_restrictions(surface.resource_group, surface.function_app)
        valid_token_command = azure.resolve_valid_token_command(
            surface.valid_token_command,
            surface.valid_token_mode,
            surface.resource_group,
            surface.function_app,
        )
        profiles = build_probe_profiles(manifest.scan, valid_token_command)

        endpoint_reports: list[EndpointReport] = []
        for endpoint in endpoints:
            exempt = is_exempt(endpoint.path_template, manifest.scan.exempt_path_patterns)
            results = []
            for profile in profiles:
                print(f"[probe] {surface.name} {endpoint.method} {endpoint.probe_path} {profile.name}")
                results.append(probe_endpoint(endpoint, manifest.scan, profile))
            endpoint_reports.append(EndpointReport(endpoint=endpoint, exempt=exempt, results=results))

        surface_reports.append(
            SurfaceReport(
                surface=surface,
                restrictions=restrictions,
                route_patterns=route_patterns,
                endpoint_reports=endpoint_reports,
            )
        )

    payload = {
        "manifest": to_plain_dict(manifest),
        "surface_reports": to_plain_dict(surface_reports),
    }

    inventory_path = write_inventory(output_dir, surface_reports)
    json_path = write_json_report(output_dir, payload)
    markdown_path = write_markdown_report(output_dir, render_markdown(manifest, surface_reports))

    print(f"[done] inventory={inventory_path}")
    print(f"[done] report-json={json_path}")
    print(f"[done] report-markdown={markdown_path}")


if __name__ == "__main__":
    main()
