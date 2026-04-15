# AGENTS.md

## Repo Purpose
`api-security-checks` is a standalone scanner for repeatable API endpoint discovery and auth-gate security checks across Azure Functions direct hosts and Azure Front Door surfaces.

## Stack

- Python 3.11+
- Azure CLI
- Standard library only at runtime

## Local Setup

- `python3 -m venv .venv && source .venv/bin/activate` (optional)
- `python3 -m pip install -e .`
- Azure CLI must already be authenticated to the target tenant/subscription

## Build / Test / Checks

- `python3 -m unittest discover -s tests -v`
- `python3 -m api_security_checks.cli --config config/heartwood.toml --output-dir output/dev`

## Key Directories

- `src/api_security_checks`
- `config`
- `docs`
- `tests`

## Sensitive / High-Risk Areas

- `config/*.toml`
- `src/api_security_checks/probing.py`
- `src/api_security_checks/azure.py`

## Before Making Changes

1. Keep the scanner non-destructive.
2. Prefer live Azure discovery over repo-doc assumptions.
3. Preserve report readability over clever output formats.
4. Update docs when the methodology or risk classification changes.

## Definition Of Done

- Discovery still works from live Azure metadata.
- Probes remain non-destructive.
- Reports clearly show inventory, tests, and results.
- Unit tests pass.
