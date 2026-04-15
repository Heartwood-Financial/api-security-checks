# Methodology

## 1. Inventory Source

The scanner treats Azure as the source of truth.

For each configured surface it pulls:

- Function inventory from `az functionapp function list`
- Route patterns from `az afd route show` for Front Door-backed surfaces
- Access restrictions from `az webapp config access-restriction show`

That gives three separate but related facts:

1. what the app has deployed
2. what the edge is exposing
3. what the raw origin allows

## 2. Surface Model

A surface is one probe target, not one codebase.

Examples:

- `helpdesk-dev-direct`
- `helpdesk-prod-frontdoor`
- `helpdesk-prod-raw-cac`
- `helpdesk-prod-raw-cae`

This is deliberate. The same Function App code can appear in multiple security contexts, and those contexts need separate results.

## 3. Endpoint Discovery

The scanner filters to HTTP-triggered functions only.

For each HTTP function it records:

- function name
- method
- auth level declared in Function metadata
- route template
- invoke URL template when Azure provides one

The scanner does **not** trust Azure Function `authLevel` as the final auth answer. Many systems use `anonymous` function triggers but enforce auth inside the app.

## 4. Safe Probe Strategy

The scanner is intentionally conservative.

### Read methods

- `GET`, `HEAD`
- sent without a request body

### Write methods

- `POST`, `PUT`, `PATCH`, `DELETE`
- sent with a malformed JSON body
- this is intended to test whether auth is enforced before validation/business logic

### Token profiles

- `anonymous`
- `wrong_audience`
- `valid_token` when configured or derivable from app settings

## 5. Result Categories

The scanner classifies each probe:

- `authorized`: valid token was accepted
- `denied`: service returned `401` or `403`
- `exposed`: anonymous or wrong-audience request returned `2xx` or `3xx`
- `potential_auth_bypass`: anonymous or wrong-audience request returned `400`, `415`, or `422`
- `not_found`: returned `404`
- `method_not_allowed`: returned `405`
- `server_error`: returned `5xx`
- `error`: local probe failure or token resolution failure

`potential_auth_bypass` is important. It means the request appears to have reached application-level parsing or validation before being denied.

## 6. Exemptions

Not every public endpoint is a bug.

The manifest supports global exempt path patterns such as:

- `/api/*/health`
- `/ops/health/*`

Exempt endpoints remain in the report but do not count as failures in the summary.

## 7. Limits

This scanner is thorough, but it is not a proof system.

Known limits:

- Placeholder path values can cause legitimate `404` responses.
- Some apps may expose aliases that are not represented in Function metadata.
- Token acquisition depends on the operator having consent and permissions.
- The scanner does not attempt destructive positive tests.
- “Authenticated on a different domain” is approximated by wrong-audience token checks unless you explicitly add a foreign-tenant token command.

## 8. Defensibility

The method is defendable because it is:

- live-discovery based
- repeatable from checked-in config
- explicit about exemptions
- explicit about safety tradeoffs
- explicit about inconclusive outcomes
