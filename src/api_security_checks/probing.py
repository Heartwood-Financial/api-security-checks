from __future__ import annotations

import subprocess
import urllib.error
import urllib.request
from functools import lru_cache

from .models import Endpoint, ProbeProfile, ProbeResult, ScanSettings


@lru_cache(maxsize=None)
def resolve_token(command: str) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        shell=True,
    )
    token = completed.stdout.strip()
    if not token:
        raise ValueError(f"Token command produced no output: {command}")
    return token


def build_probe_profiles(scan: ScanSettings, valid_token_command: str | None) -> list[ProbeProfile]:
    profiles = [
        ProbeProfile(name="anonymous", description="No Authorization header"),
        ProbeProfile(
            name="wrong_audience",
            description="Wrong-audience or unrelated token",
            token_command=scan.wrong_audience_token_command,
        ),
    ]
    if valid_token_command:
        profiles.append(
            ProbeProfile(
                name="valid_token",
                description="Expected in-tenant audience token",
                token_command=valid_token_command,
            )
        )
    return profiles


def _request_body(endpoint: Endpoint, scan: ScanSettings) -> bytes | None:
    if endpoint.method in {"GET", "HEAD"}:
        return None
    return scan.malformed_json_body.encode("utf-8")


def _classify(status_code: int | None, endpoint: Endpoint, profile: ProbeProfile) -> str:
    if status_code is None:
        return "error"

    if profile.name == "valid_token":
        if 200 <= status_code < 400:
            return "authorized"
        if status_code in {400, 404, 405, 415, 422}:
            return "reachable"
        if status_code in {401, 403}:
            return "denied"

    if 200 <= status_code < 400:
        return "exposed"

    if status_code in {401, 403}:
        return "denied"

    if status_code in {400, 415, 422} and profile.name != "valid_token":
        return "potential_auth_bypass"

    if status_code == 404:
        return "not_found"

    if status_code == 405:
        return "method_not_allowed"

    if status_code >= 500:
        return "server_error"

    return "other"


def probe_endpoint(endpoint: Endpoint, scan: ScanSettings, profile: ProbeProfile) -> ProbeResult:
    headers = {
        "User-Agent": "api-security-checks/0.1.0",
        "X-Api-Security-Check": "true",
    }

    body = _request_body(endpoint, scan)
    if body is not None:
        headers["Content-Type"] = "application/json"

    if profile.token_command:
        try:
            token = resolve_token(profile.token_command)
            headers["Authorization"] = f"Bearer {token}"
        except Exception as exc:  # pragma: no cover - exercised by integration use, not unit tests
            return ProbeResult(
                profile=profile.name,
                status_code=None,
                category="error",
                error=f"token resolution failed: {exc}",
            )

    request = urllib.request.Request(
        endpoint.probe_url,
        data=body,
        headers=headers,
        method=endpoint.method,
    )

    try:
        with urllib.request.urlopen(request, timeout=scan.request_timeout_seconds) as response:
            status_code = response.getcode()
            excerpt = response.read(200).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        excerpt = exc.read(200).decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - network/runtime dependent
        return ProbeResult(
            profile=profile.name,
            status_code=None,
            category="error",
            error=str(exc),
        )

    return ProbeResult(
        profile=profile.name,
        status_code=status_code,
        category=_classify(status_code, endpoint, profile),
        response_excerpt=excerpt.strip() or None,
    )
