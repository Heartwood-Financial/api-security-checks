# api-security-checks

`api-security-checks` is a repeatable scanner for Azure-hosted API surfaces. It discovers live HTTP endpoints from deployed Azure Functions, maps exposed prod routes through Azure Front Door, runs non-destructive auth-gate probes, and writes simple JSON and Markdown reports.

The goal is to replace one-off curl sessions with a defendable method:

1. Discover every deployed HTTP endpoint from Azure control-plane metadata.
2. Enumerate every public surface you care about: dev direct hosts, prod Front Door routes, and raw prod origins.
3. Probe each endpoint consistently for anonymous and wrong-audience access.
4. Emit a report that shows what was detected, what was tested, and what happened.

## What It Checks

- Endpoint discovery from `az functionapp function list`
- Front Door route pattern filtering from `az afd route show`
- Direct-origin access posture from `az webapp config access-restriction show`
- Anonymous requests
- Wrong-audience token requests
- Optional valid-token positive-control requests

## Safety Model

The scanner is designed to avoid state changes:

- `GET` and `HEAD` endpoints are probed with their declared method and no body.
- `POST`, `PUT`, `PATCH`, and `DELETE` endpoints are probed with their declared method but a deliberately malformed JSON body.
- The malformed body is intended to exercise auth gates before business validation and avoid successful writes.
- Path placeholders are replaced with harmless probe values such as all-zero UUIDs or `security-check`.

That still does **not** make the scan a proof of zero risk. Endpoints that require real identifiers may still return `404`, and services that authenticate after request parsing can show `400` or `415`, which the tool flags as a potential auth-gate weakness.

## Report Output

Each scan writes:

- `inventory.json`: discovered surfaces and endpoints
- `report.json`: full structured results
- `report.md`: human-readable summary and endpoint matrix

The Markdown report includes:

- surface posture summary
- direct-host access restriction summary
- per-endpoint anonymous / wrong-audience / valid-token results
- exemption marking for paths such as health endpoints

## Usage

Install in editable mode:

```bash
python3 -m pip install -e .
```

Run the default Heartwood scan:

```bash
api-security-checks --config config/heartwood.toml
```

Write results to a fixed directory:

```bash
api-security-checks --config config/heartwood.toml --output-dir output/latest
```

Limit to one or more surfaces:

```bash
api-security-checks \
  --config config/heartwood.toml \
  --surface helpdesk-prod-frontdoor \
  --surface helpdesk-prod-raw-cac
```

## Configuration

The scanner is manifest-driven. The included `config/heartwood.toml` shows the pattern:

- global scan settings
- optional shared Front Door defaults
- named surfaces

Each surface defines:

- environment name
- direct or frontdoor exposure kind
- resource group
- function app name
- base URL for probing
- optional Front Door route names
- optional token resolution mode

When `valid_token_mode = "appsetting"`, the scanner reads `AUTH_ALLOWED_AUDIENCES` from the target Function App and tries to mint a matching access token through `az account get-access-token`.

## Methodology Notes

- Discovery comes from live Azure metadata, not repo documentation.
- Health endpoints can be exempted globally so they remain visible in reports without counting as failures.
- Raw prod origin checks and prod Front Door checks should both be included. Those answer different questions.

More detail lives in [docs/methodology.md](docs/methodology.md).
