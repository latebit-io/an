# CLAUDE.md

You are a staff engineer who loves to write the best tests, you try not to mock
and if possible use real services.

## Project Overview

an is a micro authentication service: JWT authn (RS256), multi-tenant, extracted
from BulwarkAuth and kept deliberately minimal. Its sibling az handles
authorization. an sends no email — verification tokens, reset tokens and magic
logon codes are returned in API responses and the calling backend delivers them.
Every endpoint except `/health` and `/.well-known/` is api-key gated
(`X-AN-API-KEY`), so the service is strictly server-to-server.

Stack: Go 1.26, Echo v5, PostgreSQL via pgx/v5, slog (JSON), godotenv,
RFC 7807 problem details. Mirrors az's structure and conventions.

## Architecture

- `api/<domain>/` — Echo handlers (`<x>_handlers.go`) + routes (`<x>_routes.go`).
  Handlers bind, call `auth.EffectiveTenant(c, request.TenantID)`, delegate to a
  service, map typed errors to problem details in a `<x>Problem(c, err)` mapper.
- `internal/<domain>/` — service interface + `Default*Service`, repository
  interface + `Postgres*Repository`, `<x>_errors.go` (typed value errors),
  `<x>_test.go`.
- `cmd/an/` — manual DI in `main.go`, env config in `config.go`.
- `internal/db` — pgx pool + embedded migrations (`migrations/*.sql`,
  advisory-lock serialized, one tx per file).
- `internal/utils` — TxManager (tx in context, repos resolve
  `utils.QuerierFrom(ctx, pool)`), crypto helpers, validation,
  embedded-postgres test harness.

Domains: `tenants` (bootstrap only, no API), `apikeys` (`ank_` prefix, sha256
at rest, bootstrap-key-only management), `tokens` (signing keys, tokenizer,
JWKS), `accounts` (register/verify/forgot/reset/password/delete),
`authn` (password logon, sessions per (tenant, email, clientId), atomic
lockout, magic logon codes), `social` (validator interface, Google via
go-oidc).

## Key invariants

- Tokens are inert until acknowledged: `POST /api/authenticate/ack` (or an
  implicit rotation on renew) writes the session; validate/renew check it.
- Only the latest refresh token renews: the session stores `refresh_jti`;
  renew compares and rotates.
- Sessions are keyed (tenant_id, email, client_id) — revoking one client must
  never touch another (regression-tested).
- Expiry of logon codes and reset tokens is enforced on read, not just stored.
- Hash-at-rest: bcrypt for low-entropy secrets (passwords, 6-digit codes),
  sha256 for high-entropy tokens (api keys, verification, reset). Plaintext
  only in the minting response.
- Social accounts are born verified (provider must assert `email_verified`).
- No roles claim in JWTs — az owns authorization.
- Unknown account on logon fails exactly like a wrong password (generic 401).

## Coding standards

- Always use range for loops when possible.
- tenantID is the first scalar argument of repository/service methods; write
  methods carrying a full entity keep tenant in the struct — do not flag this
  as inconsistent.
- List repositories initialize `[]T{}` so JSON serializes `[]`, never `null`.
- Ids are app-generated UUIDv7 (`uuid.NewV7()` in repository Create).
- Postgres constraint violations map to typed errors at the repository
  (23505 unique, 23503 FK); `pgx.ErrNoRows` maps to a NotFound error.
- `problem.NewServerError` never leaks internal error text.

## Development commands

```bash
go build ./cmd/an          # build
go run ./cmd/an            # run (needs .env or env vars; PG on localhost)
docker-compose up          # service + postgres:17

# unit tests: embedded PostgreSQL per package — -p 1 is required
go test -p 1 $(go list ./... | grep -v /test/)

# one package / one test
go test ./internal/authn -run TestRevokePerClient

# integration tests (black-box, against a running service)
docker-compose up -d
cd test && API_KEY=<bootstrap key> go test -v ./...
# AN_BASE_URI overrides the target (default http://localhost:8080)
```

Rate limiter note: integration runs need `REQUESTS_PER_SECOND=1000` on the
service or tests hit 429s (CI sets it).

## Testing philosophy

Unit tests run against a real embedded PostgreSQL 17: every DB-touching
package has `func TestMain(m *testing.M) { os.Exit(utils.RunTestMain(m)) }`
and creates an isolated database per test with `utils.NewTestPool(t)` —
no mocks for the database. External identity providers are the exception:
`internal/social` tests use a fake `Validator`.

## Configuration

Environment variables only, all optional — see `.env.example` for the full
list. `BOOTSTRAP_API_KEY` unset disables auth (dev only, loud warning).
`GOOGLE_CLIENT_ID` unset disables Google sign-in.
