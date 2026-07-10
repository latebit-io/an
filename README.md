# an

Micro authentication service — JWT authn, kept deliberately minimal. Extracted from [BulwarkAuth](https://github.com/latebit-io/bulwarkauth) as the sibling of [az](https://github.com/latebit-io/az): an answers *who are you*, az answers *what can you do*.

- **Accounts**: register, email verification, forgot/reset, change password, soft delete
- **Password logon** with lockout after too many failures
- **Magic logon codes**: one-time 6-digit codes (passwordless; logging on with a code also verifies the account)
- **Google social sign-in**: validates the ID token, creates the account born verified
- **Token lifecycle per client**: acknowledge, validate, renew (refresh rotation), revoke — one session per `clientId`, so signing out the phone leaves the laptop signed in
- **RS256 JWTs** with a public **JWKS** endpoint so consumers verify access tokens locally
- **Multi-tenant** everywhere, with a `default` tenant out of the box

Stack: Go, Echo v5, PostgreSQL (pgx), slog. No ORM, no SMTP: **an sends no email**. Verification tokens, reset tokens and logon codes are returned in the API response — your backend delivers them however it wants. That is safe because an is server-to-server: every endpoint sits behind an api key.

## Quick start

```bash
cp .env.example .env
docker-compose up
```

Register, verify, log on:

```bash
# register (the response carries the verification token — deliver it yourself)
curl -X POST localhost:8080/api/accounts -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse"}'
# {"id":"...","email":"alice@example.com","verified":false,"verificationToken":"9f2c..."}

# verify
curl -X POST localhost:8080/api/accounts/verify -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","verificationToken":"9f2c..."}'

# password logon (clientId identifies the device/app instance)
curl -X POST localhost:8080/api/authenticate -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse","clientId":"phone"}'
# {"accessToken":"eyJ...","refreshToken":"eyJ..."}

# acknowledge the pair — tokens are inert to validate/renew until the client acks
curl -X POST localhost:8080/api/authenticate/ack -H 'Content-Type: application/json' \
  -d '{"accessToken":"eyJ...","refreshToken":"eyJ..."}'

# validate (signature + expiry + tenant + acknowledged session)
curl -X POST localhost:8080/api/authenticate/validate -H 'Content-Type: application/json' \
  -d '{"accessToken":"eyJ..."}'
```

An empty `tenantId` means the `default` tenant; pass `tenantId` in any body to scope to another tenant. More examples in `http/an.http.example`.

## Tokens

Access and refresh tokens are RS256 JWTs. Claims: `tenantId`, `clientId`, `sub` (email), `jti`, `iss`/`aud` (config), `exp`/`iat`/`nbf`. The header carries `kid` and `use` (`access`/`refresh`, enforced at validation). There is no roles claim — authorization lives in az.

- **Local verification**: `GET /.well-known/jwks.json` (unauthenticated) serves the public keys; verify signature and expiry without calling an.
- **Full validation**: `POST /api/authenticate/validate` additionally checks the session was acknowledged and not revoked.
- **Renew** rotates the refresh token: only the latest refresh token of a session can renew, so a stolen old token is dead.
- **Revoke** kills one client's session, or all of them with an empty `clientId`. Password reset and account deletion revoke every session.

Signing keys live in the database; the first boots generates one. Rotation is inserting a newer key: signing uses the latest, validation and JWKS keep serving the old ones.

## Authentication (api keys)

Set `BOOTSTRAP_API_KEY` and every endpoint except `/health` and `/.well-known/` requires a key in the `X-AN-API-KEY` header (unset means auth is disabled — dev only). Two kinds of key:

- **Bootstrap key** (the env var): the root credential. Works on any tenant and is the only key that can manage api keys.
- **Tenant keys**: minted per tenant via the api. Locked to their tenant: the tenant comes from the key, any `tenantId` in the body is ignored.

```bash
# mint a tenant-scoped key (bootstrap key required; secret is shown once)
curl -X POST localhost:8080/api/apikeys \
  -H "X-AN-API-KEY: $BOOTSTRAP_API_KEY" -H 'Content-Type: application/json' \
  -d '{"tenantId":"acme","name":"backend"}'
# {"id":"...","tenantId":"acme","name":"backend","prefix":"ank_1a2b3c4d","key":"ank_..."}
```

Keys are stored hashed (sha256 of the high-entropy token); only the `ank_` prefix is kept readable for lookup. The same hash-at-rest policy covers everything: bcrypt for passwords and logon codes, sha256 for verification and reset tokens — plaintext appears only once, in the response that minted it.

## Lockout

`MAX_FAILED_ATTEMPTS` failures (password or code, shared counter) lock the account for `LOCKOUT_DURATION_IN_SEC` — the response is `423` with the lock expiry. A successful logon or a password reset clears the counter.

## API

All endpoints take JSON bodies; errors are RFC 7807 problem details.

| Area | Endpoints |
|---|---|
| Accounts | `POST /api/accounts` · `POST /api/accounts/verify` · `POST /api/accounts/verify/resend` · `POST /api/accounts/forgot` · `POST /api/accounts/reset` · `PUT /api/accounts/password` · `PUT /api/accounts/delete` |
| Authenticate | `POST /api/authenticate` · `POST /api/authenticate/ack` · `POST /api/authenticate/renew` · `PUT /api/authenticate/revoke` · `POST /api/authenticate/validate` |
| Magic codes | `POST /api/authenticate/code/request` · `POST /api/authenticate/code` |
| Social | `POST /api/authenticate/social` (Google; set `GOOGLE_CLIENT_ID`) |
| Api keys (bootstrap key only) | `POST /api/apikeys` · `POST /api/apikeys/list` · `PUT /api/apikeys/delete` |
| Open | `GET /health` · `GET /.well-known/jwks.json` |

## Development

```bash
# unit tests (embedded PostgreSQL — real database per test, no mocks)
go test -p 1 $(go list ./... | grep -v /test/)

# integration tests against a running service
docker-compose up -d
cd test && API_KEY=<bootstrap key> go test -v ./...
```

Configuration is environment variables only — see `.env.example`. Nothing is required at boot; sensible defaults throughout.

## License

MIT
