#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI is required. Install 'az' first." >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Azure CLI is not signed in. Run 'az login' first." >&2
  exit 1
fi

current_subscription_id="$(az account show --query id -o tsv)"
current_subscription_name="$(az account show --query name -o tsv)"
current_tenant_id="$(az account show --query tenantId -o tsv)"

required_subscription_id="${API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_ID:-}"
required_subscription_name="${API_SECURITY_CHECKS_REQUIRED_AZURE_SUBSCRIPTION_NAME:-}"
required_tenant_id="${API_SECURITY_CHECKS_REQUIRED_AZURE_TENANT_ID:-}"

if [[ -n "$required_tenant_id" && "$current_tenant_id" != "$required_tenant_id" ]]; then
  echo "Wrong Azure tenant. Expected $required_tenant_id but found $current_tenant_id." >&2
  exit 1
fi

if [[ -n "$required_subscription_id" && "$current_subscription_id" != "$required_subscription_id" ]]; then
  echo "Wrong Azure subscription. Expected $required_subscription_id but found $current_subscription_id." >&2
  exit 1
fi

if [[ -n "$required_subscription_name" && "$current_subscription_name" != "$required_subscription_name" ]]; then
  echo "Wrong Azure subscription name. Expected '$required_subscription_name' but found '$current_subscription_name'." >&2
  exit 1
fi

echo "Azure context: $current_subscription_name ($current_subscription_id) / tenant $current_tenant_id"

if [[ ! -x .venv/bin/api-security-checks ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -e .
fi

cmd=(.venv/bin/api-security-checks)

if [[ -n "${API_SECURITY_CHECKS_CONFIG:-}" ]]; then
  cmd+=(--config "$API_SECURITY_CHECKS_CONFIG")
fi

if [[ -n "${API_SECURITY_CHECKS_OUTPUT_DIR:-}" ]]; then
  cmd+=(--output-dir "$API_SECURITY_CHECKS_OUTPUT_DIR")
fi

if [[ -n "${API_SECURITY_CHECKS_SURFACES:-}" ]]; then
  IFS=',' read -r -a surfaces <<< "${API_SECURITY_CHECKS_SURFACES}"
  for surface in "${surfaces[@]}"; do
    if [[ -n "$surface" ]]; then
      cmd+=(--surface "$surface")
    fi
  done
fi

exec "${cmd[@]}" "$@"
