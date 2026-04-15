from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from typing import Any

from .models import FrontDoorDefaults, SurfaceRestrictions


def run_az_json(args: list[str]) -> Any:
    completed = subprocess.run(
        ["az", *args, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    stdout = completed.stdout.strip()
    return json.loads(stdout) if stdout else None


def run_az_tsv(args: list[str]) -> str:
    completed = subprocess.run(
        ["az", *args, "-o", "tsv"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


@lru_cache(maxsize=None)
def list_functions(resource_group: str, function_app: str) -> list[dict[str, Any]]:
    return list(run_az_json(["functionapp", "function", "list", "-g", resource_group, "-n", function_app]) or [])


@lru_cache(maxsize=None)
def list_app_settings(resource_group: str, function_app: str) -> dict[str, str]:
    settings = run_az_json(["functionapp", "config", "appsettings", "list", "-g", resource_group, "-n", function_app]) or []
    result: dict[str, str] = {}
    for setting in settings:
        name = setting.get("name")
        value = setting.get("value")
        if name:
            result[str(name)] = "" if value is None else str(value)
    return result


@lru_cache(maxsize=None)
def get_access_restrictions(resource_group: str, function_app: str) -> SurfaceRestrictions:
    payload = run_az_json(["webapp", "config", "access-restriction", "show", "-g", resource_group, "-n", function_app]) or {}
    rules = []
    for rule in payload.get("ipSecurityRestrictions", []) or []:
        if str(rule.get("action") or "").lower() != "allow":
            continue
        fdids = (((rule.get("headers") or {}).get("x-azure-fdid") or [None]))
        rules.append(
            {
                "name": rule.get("name"),
                "action": rule.get("action"),
                "ipAddress": rule.get("ipAddress"),
                "fdid": fdids[0],
            }
        )

    return SurfaceRestrictions(
        default_action=payload.get("ipSecurityRestrictionsDefaultAction"),
        scm_default_action=payload.get("scmIpSecurityRestrictionsDefaultAction"),
        scm_use_main=payload.get("scmIpSecurityRestrictionsUseMain"),
        allow_rules=rules,
    )


@lru_cache(maxsize=None)
def get_frontdoor_route_patterns(
    resource_group: str,
    profile_name: str,
    endpoint_name: str,
    route_name: str,
) -> list[str]:
    payload = run_az_json(
        [
            "afd",
            "route",
            "show",
            "--resource-group",
            resource_group,
            "--profile-name",
            profile_name,
            "--endpoint-name",
            endpoint_name,
            "--route-name",
            route_name,
        ]
    ) or {}
    return [str(item) for item in (payload.get("patternsToMatch") or [])]


def resolve_valid_token_command(
    explicit_command: str | None,
    valid_token_mode: str | None,
    resource_group: str,
    function_app: str,
) -> str | None:
    if explicit_command:
        return explicit_command
    if valid_token_mode != "appsetting":
        return None

    settings = list_app_settings(resource_group, function_app)
    audience_blob = settings.get("AUTH_ALLOWED_AUDIENCES", "")
    audiences = [item.strip() for item in audience_blob.split(",") if item.strip()]
    if not audiences:
        return None

    preferred = next((value for value in audiences if value.startswith("api://")), audiences[0])
    if preferred.endswith("/.default"):
        scope = preferred
    elif preferred.startswith("api://") or preferred.startswith("https://"):
        scope = f"{preferred}/.default"
    else:
        scope = f"api://{preferred}/.default"

    return f"az account get-access-token --scope {scope} --query accessToken -o tsv"


def frontdoor_base_url(defaults: FrontDoorDefaults) -> str:
    return defaults.base_url.rstrip("/")
