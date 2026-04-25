from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class FrontDoorDefaults:
    resource_group: str
    profile_name: str
    endpoint_name: str
    base_url: str


@dataclass(slots=True)
class ScanSettings:
    title: str
    wrong_audience_token_command: str
    exempt_path_patterns: list[str] = field(default_factory=list)
    request_timeout_seconds: int = 20
    placeholder_uuid: str = "00000000-0000-0000-0000-000000000000"
    malformed_json_body: str = '{"probe":'
    capture_response_excerpt_bytes: int = 0


@dataclass(slots=True)
class SurfaceConfig:
    name: str
    environment: str
    kind: str
    resource_group: str
    function_app: str
    base_url: str | None = None
    route_names: list[str] = field(default_factory=list)
    notes: str | None = None
    valid_token_command: str | None = None
    valid_token_mode: str | None = None


@dataclass(slots=True)
class Manifest:
    scan: ScanSettings
    frontdoor_defaults: FrontDoorDefaults | None
    surfaces: list[SurfaceConfig]


@dataclass(slots=True)
class SurfaceRestrictions:
    default_action: str | None = None
    scm_default_action: str | None = None
    scm_use_main: bool | None = None
    allow_rules: list[dict[str, Any]] = field(default_factory=list)

    def has_public_allow_rule(self) -> bool:
        for rule in self.allow_rules:
            ip_address = str(rule.get("ipAddress") or "")
            fdid = str(rule.get("fdid") or "")
            if ip_address == "AzureFrontDoor.Backend" and fdid:
                continue
            return True
        return False


@dataclass(slots=True)
class Endpoint:
    surface_name: str
    environment: str
    kind: str
    function_app: str
    resource_group: str
    function_name: str
    method: str
    path_template: str
    probe_path: str
    probe_url: str
    auth_level: str | None
    invoke_url_template: str | None
    notes: str | None = None
    route_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProbeProfile:
    name: str
    description: str
    token_command: str | None = None


@dataclass(slots=True)
class ProbeResult:
    profile: str
    status_code: int | None
    category: str
    error: str | None = None
    response_excerpt: str | None = None


@dataclass(slots=True)
class EndpointReport:
    endpoint: Endpoint
    exempt: bool
    results: list[ProbeResult]


@dataclass(slots=True)
class SurfaceReport:
    surface: SurfaceConfig
    restrictions: SurfaceRestrictions | None
    route_patterns: list[str]
    endpoint_reports: list[EndpointReport]


def to_plain_dict(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, list):
        return [to_plain_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain_dict(item) for key, item in value.items()}
    return value
