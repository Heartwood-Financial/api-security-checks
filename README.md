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
- Response body capture is disabled by default; reports classify by status code unless you explicitly enable excerpts.

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

## Quick Start

For this repo, the easiest operator flow is:

1. Create a local `.env` from `.env.example`.
2. Make sure Azure CLI is signed in to the expected tenant and subscription.
3. Run `./scripts/run-heartwood-scan.sh`.

The runner script will:

- load `.env`
- verify Azure CLI login context
- create `.venv` if needed
- install the package in editable mode if needed
- run the scanner with your local defaults

On a fresh clone:

```bash
cp .env.example .env
./scripts/run-heartwood-scan.sh
```

## Local Setup

Install manually if you want direct CLI access:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

Before running scans, Azure CLI needs to be authenticated:

```bash
az login
az account show -o table
```

If you need to switch subscriptions:

```bash
az account set --subscription "<subscription-name-or-id>"
```

## .env Setup

`.env` is local-only and ignored by git. The committed template is `.env.example`.

The scanner and runner understand these operator defaults:

- `API_SECURITY_CHECKS_CONFIG`: manifest path
- `API_SECURITY_CHECKS_OUTPUT_DIR`: report directory
- `API_SECURITY_CHECKS_SURFACES`: optional comma-separated surface filter
- `API_SECURITY_CHECKS_DISCOVER_DIRECT_FUNCTIONAPPS`: set to `1` to add live direct Function App hosts from Azure inventory
- `API_SECURITY_CHECKS_DIRECT_DISCOVERY_ONLY`: set to `1` to scan only auto-discovered direct Function App hosts
- `API_SECURITY_CHECKS_DIRECT_DISCOVERY_STATES`: comma-separated Function App states to include, defaults to `Running`
- `API_SECURITY_CHECKS_SKIP_VALID_TOKEN`: set to `1` to focus on anonymous and wrong-audience probes only
- `API_SECURITY_CHECKS_REQUIRED_AZURE_TENANT_ID`: fail fast if `az` is on the wrong tenant
- `API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_ID`: fail fast if `az` is on the wrong subscription
- `API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_NAME`: friendly label used in preflight messages
- `API_SECURITY_CHECKS_WRONG_AUDIENCE_TOKEN_COMMAND`: optional override for the wrong-audience probe command

Example:

```dotenv
API_SECURITY_CHECKS_CONFIG=config/heartwood.toml
API_SECURITY_CHECKS_OUTPUT_DIR=output/latest
API_SECURITY_CHECKS_SURFACES=
API_SECURITY_CHECKS_DISCOVER_DIRECT_FUNCTIONAPPS=0
API_SECURITY_CHECKS_DIRECT_DISCOVERY_ONLY=0
API_SECURITY_CHECKS_DIRECT_DISCOVERY_STATES=Running
API_SECURITY_CHECKS_SKIP_VALID_TOKEN=0
API_SECURITY_CHECKS_REQUIRED_AZURE_TENANT_ID=<tenant-id>
API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_ID=<subscription-id>
API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_NAME="<subscription-name>"
```

## Usage

Run with the local `.env` defaults:

```bash
./scripts/run-heartwood-scan.sh
```

Run the CLI directly:

```bash
api-security-checks
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

Load a non-default env file:

```bash
api-security-checks --env-file .env.prod-check
```

Scan all running Function Apps directly from the current Azure subscription:

```bash
api-security-checks \
  --discover-direct-functionapps \
  --direct-discovery-only \
  --skip-valid-token \
  --output-dir output/direct-latest
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

The CLI auto-loads `./.env` when present. Command-line arguments still win if you pass explicit flags.

## Methodology Notes

- Discovery comes from live Azure metadata, not repo documentation.
- Health endpoints can be exempted globally so they remain visible in reports without counting as failures.
- Raw prod origin checks and prod Front Door checks should both be included. Those answer different questions.

More detail lives in [docs/methodology.md](docs/methodology.md).
