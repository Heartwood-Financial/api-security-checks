from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import azure
from .matching import matches_any_pattern, path_from_url, render_probe_path
from .models import Endpoint, FrontDoorDefaults, SurfaceConfig


def infer_environment(resource_group: str, function_app: str) -> str:
    haystack = f"{resource_group} {function_app}".lower()
    for environment in ("prod", "dev", "uat", "sit", "test", "qa"):
        if f"-{environment}-" in haystack or haystack.endswith(f"-{environment}") or f"_{environment}_" in haystack:
            return environment
    return "unknown"


def discover_direct_functionapp_surfaces(
    existing_surfaces: list[SurfaceConfig],
    states: set[str],
) -> list[SurfaceConfig]:
    existing_direct = {
        (surface.resource_group.lower(), surface.function_app.lower())
        for surface in existing_surfaces
        if surface.kind == "direct"
    }
    discovered: list[SurfaceConfig] = []

    for app in azure.list_function_apps():
        state = str(app.get("state") or "")
        if states and state not in states:
            continue

        name = str(app.get("name") or "")
        resource_group = str(app.get("resourceGroup") or "")
        default_host_name = str(app.get("defaultHostName") or "")
        if not name or not resource_group or not default_host_name:
            continue

        key = (resource_group.lower(), name.lower())
        if key in existing_direct:
            continue

        discovered.append(
            SurfaceConfig(
                name=f"direct-{name}",
                environment=infer_environment(resource_group, name),
                kind="direct",
                resource_group=resource_group,
                function_app=name,
                base_url=f"https://{default_host_name}",
                notes="Auto-discovered direct Function App surface from Azure subscription inventory.",
                valid_token_mode="appsetting",
            )
        )

    return sorted(discovered, key=lambda surface: (surface.environment, surface.resource_group, surface.function_app))


def _http_bindings(function_payload: dict[str, Any]) -> list[dict[str, Any]]:
    bindings = ((function_payload.get("config") or {}).get("bindings") or [])
    return [binding for binding in bindings if binding.get("type") == "httpTrigger"]


def discover_surface_endpoints(
    surface: SurfaceConfig,
    placeholder_uuid: str,
    frontdoor_defaults: FrontDoorDefaults | None = None,
) -> tuple[list[Endpoint], list[str]]:
    functions = azure.list_functions(surface.resource_group, surface.function_app)

    route_patterns: list[str] = []
    if surface.kind == "frontdoor":
        if not frontdoor_defaults:
            raise ValueError(f"Surface {surface.name} requires frontdoor_defaults")
        if not surface.route_names:
            raise ValueError(f"Surface {surface.name} is frontdoor-backed but has no route_names")
        for route_name in surface.route_names:
            route_patterns.extend(
                azure.get_frontdoor_route_patterns(
                    frontdoor_defaults.resource_group,
                    frontdoor_defaults.profile_name,
                    frontdoor_defaults.endpoint_name,
                    route_name,
                )
            )

    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str, str]] = set()

    for function in functions:
        for binding in _http_bindings(function):
            methods = [str(item).upper() for item in (binding.get("methods") or ["GET"])]
            invoke_url = function.get("invokeUrlTemplate")
            if invoke_url:
                path_template = path_from_url(str(invoke_url))
            else:
                route = str(binding.get("route") or "").lstrip("/")
                path_template = f"/api/{route}" if route else "/api"

            if route_patterns and not matches_any_pattern(path_template, route_patterns):
                continue

            base_url = surface.base_url
            if surface.kind == "frontdoor" and frontdoor_defaults:
                base_url = azure.frontdoor_base_url(frontdoor_defaults)
            if not base_url:
                raise ValueError(f"Surface {surface.name} has no base_url")

            probe_path = render_probe_path(path_template, placeholder_uuid)
            probe_url = f"{base_url.rstrip('/')}{probe_path}"

            for method in methods:
                unique_key = (surface.name, method, path_template)
                if unique_key in seen:
                    continue
                seen.add(unique_key)
                endpoints.append(
                    Endpoint(
                        surface_name=surface.name,
                        environment=surface.environment,
                        kind=surface.kind,
                        function_app=surface.function_app,
                        resource_group=surface.resource_group,
                        function_name=str(function.get("name") or ""),
                        method=method,
                        path_template=path_template,
                        probe_path=probe_path,
                        probe_url=probe_url,
                        auth_level=binding.get("authLevel"),
                        invoke_url_template=invoke_url,
                        notes=surface.notes,
                        route_names=list(surface.route_names),
                    )
                )

    endpoints.sort(key=lambda item: (item.path_template, item.method))
    return endpoints, sorted(set(route_patterns))


def summarize_endpoint_counts(endpoints: list[Endpoint]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for endpoint in endpoints:
        counts[endpoint.method] += 1
    return dict(sorted(counts.items()))
