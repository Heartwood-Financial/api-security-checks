from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .matching import matches_any_pattern
from .models import EndpointReport, Manifest, SurfaceReport, to_plain_dict


def is_exempt(path_template: str, patterns: list[str]) -> bool:
    return matches_any_pattern(path_template, patterns)


def summarize_findings(surface_reports: list[SurfaceReport]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for surface_report in surface_reports:
        for endpoint_report in surface_report.endpoint_reports:
            if endpoint_report.exempt:
                counter["exempt"] += 1
                continue
            for result in endpoint_report.results:
                if result.profile in {"anonymous", "wrong_audience"}:
                    counter[result.category] += 1
    return counter


def write_json_report(output_dir: Path, payload: dict) -> Path:
    path = output_dir / "report.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def render_markdown(manifest: Manifest, surface_reports: list[SurfaceReport]) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    findings = summarize_findings(surface_reports)

    lines: list[str] = []
    lines.append(f"# {manifest.scan.title}")
    lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for key in sorted(findings):
        lines.append(f"| {key} | {findings[key]} |")
    lines.append("")
    lines.append("## Surface Posture")
    lines.append("")
    lines.append("| Surface | Environment | Kind | Function App | Public Allow Rule | Route Patterns |")
    lines.append("|---|---|---|---|---|---|")
    for surface_report in surface_reports:
        restrictions = surface_report.restrictions
        public_rule = "n/a"
        if restrictions is not None:
            public_rule = "yes" if restrictions.has_public_allow_rule() else "no"
        route_patterns = ", ".join(surface_report.route_patterns) or "-"
        lines.append(
            f"| {surface_report.surface.name} | {surface_report.surface.environment} | "
            f"{surface_report.surface.kind} | {surface_report.surface.function_app} | {public_rule} | {route_patterns} |"
        )
    lines.append("")

    for surface_report in surface_reports:
        lines.append(f"## {surface_report.surface.name}")
        lines.append("")
        lines.append(
            f"- Function App: `{surface_report.surface.function_app}` in `{surface_report.surface.resource_group}`"
        )
        lines.append(f"- Base URL: `{surface_report.surface.base_url or 'frontdoor default'}`")
        if surface_report.surface.notes:
            lines.append(f"- Notes: {surface_report.surface.notes}")
        if surface_report.route_patterns:
            lines.append(f"- Live route patterns: `{', '.join(surface_report.route_patterns)}`")
        if surface_report.restrictions is not None:
            allow_rules = ", ".join(
                f"{rule['name']}:{rule['ipAddress']}" for rule in surface_report.restrictions.allow_rules
            ) or "none"
            lines.append(f"- Main-site default action: `{surface_report.restrictions.default_action}`")
            lines.append(f"- SCM default action: `{surface_report.restrictions.scm_default_action}`")
            lines.append(f"- Allow rules: `{allow_rules}`")
        lines.append("")
        lines.append("| Method | Path Template | Exempt | Anonymous | Wrong Audience | Valid Token |")
        lines.append("|---|---|---|---|---|---|")
        for endpoint_report in surface_report.endpoint_reports:
            result_map = {result.profile: result for result in endpoint_report.results}
            lines.append(
                "| "
                + " | ".join(
                    [
                        endpoint_report.endpoint.method,
                        f"`{endpoint_report.endpoint.path_template}`",
                        "yes" if endpoint_report.exempt else "no",
                        _render_result(result_map.get("anonymous")),
                        _render_result(result_map.get("wrong_audience")),
                        _render_result(result_map.get("valid_token")),
                    ]
                )
                + " |"
            )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def _render_result(result) -> str:
    if result is None:
        return "-"
    code = "n/a" if result.status_code is None else str(result.status_code)
    return f"`{code} {result.category}`"


def write_markdown_report(output_dir: Path, content: str) -> Path:
    path = output_dir / "report.md"
    path.write_text(content, encoding="utf-8")
    return path


def write_inventory(output_dir: Path, surface_reports: list[SurfaceReport]) -> Path:
    inventory = []
    for surface_report in surface_reports:
        inventory.append(
            {
                "surface": to_plain_dict(surface_report.surface),
                "restrictions": to_plain_dict(surface_report.restrictions),
                "route_patterns": surface_report.route_patterns,
                "endpoints": [to_plain_dict(report.endpoint) for report in surface_report.endpoint_reports],
            }
        )
    path = output_dir / "inventory.json"
    path.write_text(json.dumps(inventory, indent=2, sort_keys=True), encoding="utf-8")
    return path
