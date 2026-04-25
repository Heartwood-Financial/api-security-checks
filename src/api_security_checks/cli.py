from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import azure
from .config import load_manifest
from .discovery import discover_direct_functionapp_surfaces, discover_surface_endpoints
from .envfile import load_env_file
from .models import EndpointReport, SurfaceReport, to_plain_dict
from .probing import build_probe_profiles, probe_endpoint
from .report import is_exempt, render_markdown, write_inventory, write_json_report, write_markdown_report


def _split_surface_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _detect_env_file(argv: list[str]) -> Path | None:
    for index, arg in enumerate(argv):
        if arg == "--env-file" and index + 1 < len(argv):
            return Path(argv[index + 1])
        if arg.startswith("--env-file="):
            return Path(arg.split("=", 1)[1])

    configured = os.environ.get("API_SECURITY_CHECKS_ENV_FILE")
    if configured:
        return Path(configured)

    default = Path(".env")
    if default.is_file():
        return default
    return None


def _preload_env(argv: list[str]) -> Path | None:
    env_file = _detect_env_file(argv)
    if env_file is None:
        return None
    if not env_file.is_file():
        raise SystemExit(f"Env file not found: {env_file}")
    load_env_file(env_file)
    return env_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover and probe Azure API surfaces.")
    parser.add_argument(
        "--env-file",
        default=os.environ.get("API_SECURITY_CHECKS_ENV_FILE"),
        help="Load defaults from a .env file. Defaults to ./.env when present.",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("API_SECURITY_CHECKS_CONFIG", "config/heartwood.toml"),
        help="Path to the TOML manifest that defines scanned surfaces.",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("API_SECURITY_CHECKS_OUTPUT_DIR"),
        help="Directory for generated reports. Defaults to output/<timestamp>.",
    )
    parser.add_argument(
        "--surface",
        action="append",
        default=_split_surface_list(os.environ.get("API_SECURITY_CHECKS_SURFACES")),
        help="Optional surface name filter. Repeat to include multiple surfaces.",
    )
    parser.add_argument(
        "--discover-direct-functionapps",
        action="store_true",
        default=_env_bool("API_SECURITY_CHECKS_DISCOVER_DIRECT_FUNCTIONAPPS"),
        help="Auto-discover running Azure Function Apps and add their direct public hosts as surfaces.",
    )
    parser.add_argument(
        "--direct-discovery-only",
        action="store_true",
        default=_env_bool("API_SECURITY_CHECKS_DIRECT_DISCOVERY_ONLY"),
        help="Scan only auto-discovered direct Function App surfaces.",
    )
    parser.add_argument(
        "--direct-discovery-state",
        action="append",
        default=None,
        help="Function App state to include during direct discovery. Defaults to Running. Repeat to include more.",
    )
    parser.add_argument(
        "--skip-valid-token",
        action="store_true",
        default=_env_bool("API_SECURITY_CHECKS_SKIP_VALID_TOKEN"),
        help="Skip expected-audience positive-control token probes.",
    )
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("output") / stamp


def main(argv: list[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    _preload_env(raw_argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    manifest = load_manifest(args.config)
    selected = {name for name in args.surface}
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    surfaces = [] if args.direct_discovery_only else list(manifest.surfaces)
    if args.discover_direct_functionapps or args.direct_discovery_only:
        state_names = set(
            args.direct_discovery_state
            or _split_surface_list(os.environ.get("API_SECURITY_CHECKS_DIRECT_DISCOVERY_STATES"))
            or ["Running"]
        )
        discovered = discover_direct_functionapp_surfaces(surfaces, states=state_names)
        print(f"[discover-direct] added {len(discovered)} direct Function App surfaces", flush=True)
        surfaces.extend(discovered)

    surface_reports: list[SurfaceReport] = []

    for surface in surfaces:
        if selected and surface.name not in selected:
            continue

        print(f"[discover] {surface.name}", flush=True)
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
        if args.skip_valid_token:
            valid_token_command = None
        profiles = build_probe_profiles(manifest.scan, valid_token_command)

        endpoint_reports: list[EndpointReport] = []
        for endpoint in endpoints:
            exempt = is_exempt(endpoint.path_template, manifest.scan.exempt_path_patterns)
            results = []
            for profile in profiles:
                print(f"[probe] {surface.name} {endpoint.method} {endpoint.probe_path} {profile.name}", flush=True)
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

    print(f"[done] inventory={inventory_path}", flush=True)
    print(f"[done] report-json={json_path}", flush=True)
    print(f"[done] report-markdown={markdown_path}", flush=True)


if __name__ == "__main__":
    main()
