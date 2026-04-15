from __future__ import annotations

import os
from pathlib import Path


def parse_env_text(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ValueError(f"Invalid .env line: {raw_line}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def load_env_file(path: str | Path, environ: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ if environ is None else environ
    payload = parse_env_text(Path(path).read_text(encoding="utf-8"))
    for key, value in payload.items():
        env.setdefault(key, value)
    return payload
