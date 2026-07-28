# Plan: OIDC provider surface

Add an OpenID Connect provider surface to `an`, so it can act as a login provider for browsers and for services that only speak OIDC.

Status: proposed 2026-07-27, revised 2026-07-27 after a review against the code. Driven by the demarkus hosted service, which needs a central issuer, but useful to any consumer of `an`.

## Why

`an` today is an authentication **API**: server-to-server, api-key gated, and every calling app collects the user's password itself and posts it to `/api/authenticate`. That makes every app a credential-handling surface, and it means `an` cannot be used at all by software that only speaks OIDC.

Two concrete drivers:

- **The demarkus broker only accepts an OIDC issuer.** There is no api-key path into it. A hosted tenant's broker must point at a real issuer to authenticate anyone, which makes this a hard dependency for hosting.
- **Passwords stop touching client apps.** Under the authorization code flow the credential only ever reaches `an`. Every app that switches deletes password-handling code rather than accumulating it.

Secondary, but they follow once the browser session below exists: single sign-on across apps that share the issuer, and login features (MFA, magic codes, social, lockout) implemented once in `an` instead of per app.

The api-key surface does not go away. OIDC is an additional front door for browser-driven login; server-to-server callers keep using the existing endpoints.

## What already exists

`an` is further along than it looks. Present today:

- Accounts, verification, reset, lockout.
- Password logon, passwordless magic codes, Google social sign-in.
- RS256 signing and a public JWKS endpoint at `/.well-known/jwks.json`.
- Per-`clientId` session lifecycle: acknowledge, validate, renew with refresh rotation, revoke.
- Multi-tenancy throughout.

Signing and key publication are the parts implementers most often get wrong, and they are done. What is missing is the OAuth2 code-flow surface, claim shaping, and a browser-facing login surface of any kind: `an` has never served HTML or set a cookie.

## Decisions taken up front

These six shape everything downstream and are expensive to reverse once an external relying party depends on the issuer. They are settled here rather than left open.

### Subject identity

**`sub` is the account UUID, not the email.** Today `DefaultTokenizer.registeredClaims` puts the email in `Subject`. OIDC requires a subject that is stable within the issuer and never reassigned; an email is neither, because addresses change and get reused. `Account.ID` is already a UUIDv7 and is the right value.

Every relying party keys its own user table on `sub`, so this cannot be changed after the first consumer ships. Email continues to travel as the `email` claim, which is where relying parties expect a mutable address.

The rest of the service stays keyed on email: repositories, sessions, and service signatures do not change. Only the OIDC minting path resolves an account id and uses it as `sub`. Reworking the internal keying is a separate piece of work and is not a prerequisite.

### Access tokens on the OIDC surface are opaque

The existing `Tokenizer` validates with a single configured audience (`AUDIENCE`, defaulting to `an`). OIDC requires the `id_token` audience to be the relying party's client id, which the current signing and validation path cannot express for two different clients at once.

So the two surfaces do not share tokens:

- `id_token`: RS256, signed with the existing keys and published JWKS, `aud` = client id, `iss` = the tenant issuer below.
- Access token from `/token`: **opaque**, stored, looked up on use. This sidesteps the audience collision entirely, makes UserInfo authentication trivial, and leaves the existing JWT access token semantics untouched for api-key callers.
- The existing api-key access and refresh tokens are unchanged.

Minting the `id_token` is a new method alongside the current ones, not a change to `CreateAccessToken`.

### Issuer shape is per tenant, from day one

`ISSUER` is one env string, discovery is one document per issuer, and a relying party's configured issuer URL must match the `iss` claim exactly. Retrofitting a tenant into the issuer URL later breaks every registered client, so the tenant goes into the URL now even while only one tenant uses it.

- Issuer: `https://<host>/t/<tenantId>`
- Discovery: `/t/<tenantId>/.well-known/openid-configuration`
- JWKS: `/t/<tenantId>/.well-known/jwks.json`, serving the same global key set. Keys are not per tenant; only the URL is. The existing `/.well-known/jwks.json` stays and serves the same document.
- `/t/<tenantId>/authorize`, `/t/<tenantId>/token`, `/t/<tenantId>/userinfo`, `/t/<tenantId>/logout`.

`DOMAIN` gains a companion `PUBLIC_BASE_URL` used to build absolute URLs in discovery and in redirects. `ISSUER` keeps its current meaning for the api-key token path.

### OIDC sessions are their own table

The existing `sessions` table is one row per `(tenant_id, email, client_id)` and `Upsert` overwrites on conflict, so a second sign-in evicts the first. That is tolerable for server-to-server callers and wrong for an SSO issuer, where the same person is legitimately signed in from a phone and a laptop at once.

A new `oidc_sessions` table holds one row per issued grant, keyed by its own id, carrying `(tenant_id, account_id, client_id, refresh token hash, expires)`. Many rows per triple are expected.

The "inert until acknowledged" invariant does not apply here. Tokens returned from `/token` are live on return; there is no acknowledgement step in the code flow. The existing invariant and its regression tests are untouched.

### Browser session and logout are in scope

Single sign-on is not free. It requires `an` to hold its own browser session so that a second `/authorize` from a different app does not re-prompt. That means a session cookie (`Secure`, `HttpOnly`, `SameSite=Lax`), a store for it, a lifetime, and CSRF protection on the login form.

Once that session exists, there must be a way to end it, so **RP-initiated logout (`end_session_endpoint`) moves into scope**. Shipping SSO without it leaves users with a session they cannot terminate. Front-channel and back-channel logout notification to other relying parties stays deferred.

### The api-key gate gains its first exceptions

`api/auth.Middleware` currently exempts only `/health` and paths under `/.well-known/`. The OIDC surface is browser and relying-party facing and cannot carry `X-AN-API-KEY`. The exemption list grows to:

`/t/<tenantId>/authorize`, `/token`, `/userinfo`, `/logout`, and the login UI's form post and static assets.

`/token` and `/userinfo` authenticate the client (secret or PKCE) instead; `/authorize` authenticates the user. This is a deliberate amendment to the invariant recorded in `CLAUDE.md`, which is updated in the same change rather than left contradicting the code.

Consequence: these routes face public traffic. `REQUESTS_PER_SECOND` defaults to 20 for the whole service, which is not a sensible public login budget. The OIDC routes get their own limiter bucket, and failed logins at `/authorize` feed the existing lockout counters.

## Scope

A minimal conformant issuer. Deliberately not all of OIDC.

### Build

| Piece | Notes |
|---|---|
| `/.well-known/openid-configuration` | Per tenant. Discovery, so clients stop hardcoding endpoints |
| `/authorize` | The browser-facing half, with a login UI. The only place credentials are entered |
| Login UI | HTML templates, static assets, CSP, form CSRF token, error rendering. The service's first non-JSON surface |
| Browser session cookie | The thing that makes SSO real. Own store, own lifetime |
| Authorization code store | Single-use, short TTL, bound to client, redirect URI, PKCE challenge, nonce, and subject |
| `/token` | Code exchange with client authentication, plus the `refresh_token` grant |
| `/userinfo` | Small, given the claims are already computed. See below |
| `/logout` | RP-initiated, `end_session_endpoint` in discovery |
| `id_token` minting | `sub` = account id; `email`, `email_verified`, `groups`, `name`; `aud` = client id |
| Account `name` | Migration, plus registration and profile update. No source exists today |
| OIDC client registry | Client id, secret hash, redirect URIs, allowed scopes, first-party flag, per tenant |
| `state`, `nonce`, PKCE | CSRF and replay defence |

### Defer

- Dynamic client registration. Clients are registered out of band.
- Front-channel and back-channel logout notification. RP-initiated logout is in scope.
- Consent screens. First-party clients only to begin with, enforced by a `first_party` flag on the client record so that registering a third-party client later fails loudly instead of silently skipping consent.
- Scopes beyond a fixed set (`openid`, `email`, `profile`, `groups`, `offline_access`).
- Re-keying the internal model from email to account id.

### Why UserInfo is no longer deferred

The first consumer never calls it, but relying-party libraries commonly fetch it whenever `profile` or `email` is requested, and OP conformance testing exercises it. The claims are already computed for the `id_token`, so the endpoint is a lookup and a serialization behind opaque-token authentication. Deferring it buys nothing and costs interoperability with clients other than the broker.

## The claims constraint

**Claims must be in the `id_token`.** The demarkus broker reads them from the id_token only and never calls UserInfo. This is not incidental: the appliance's bundled Authelia configuration carries a mandatory claims policy pinning exactly `email`, `email_verified`, `groups`, and `name` into the id_token, precisely because of this.

Getting it wrong produces logins that fail opaquely rather than loudly, so it is worth a conformance test rather than a manual check.

Sources: `email` and `email_verified` map directly to `Account.Email` and `Account.Verified`. `name` does not exist yet and is the migration listed above. `groups` comes from `az`, below.

## Do not hand-roll the protocol

Use a provider library for the OAuth2 and OIDC machinery: code exchange, client authentication, PKCE, token endpoint semantics, error responses.

**Decided: `github.com/zitadel/oidc/v3`, package `pkg/op`.** Ory Fosite was the expected answer and lost on evidence. Both were pulled and their storage interfaces read before choosing.

| | Ory Fosite v0.49.0 | zitadel/oidc v3.48.1 |
|---|---|---|
| Last release | 2024-12-12, 19 months ago | 2026-07-27, same day |
| External modules pulled in | 32 | 14 |
| Storage methods to implement | 19 | ~25 |
| What storage traffics in | `fosite.Requester`, opaque, serialize and rehydrate | your own structs behind small interfaces |
| Discovery, UserInfo, end_session | not included, Ory Hydra implements them on top | included |
| Access token shape | JWT or opaque via strategy | opaque native, JWT opt-in |

The method count favours Fosite and is the least important row. The deciding one is what the methods carry. Fosite hands every storage call a `fosite.Requester` to persist and rehydrate, which is the serialized blob this repo has no other instance of. `op.Storage` instead calls methods that return interfaces (`AuthRequest`, `Client`, `TokenRequest`, `RefreshTokenRequest`) which `an`'s own structs satisfy, so the authorization request persists as typed columns in a normal `PostgresOidcRequestRepository` alongside every other repository here.

The rest follows the decisions already taken:

- `CreateAccessToken` returns a token id, so **opaque access tokens are the native path**, exactly as decided above. Fosite would need a custom strategy to get there.
- `SigningKey`, `SignatureAlgorithms`, and `KeySet` are storage callbacks, so `an` keeps its existing signing keys, rotation model, and JWKS rather than adopting the library's.
- `SetUserinfoFromRequest` and `GetPrivateClaimsFromScopes` are where `email`, `email_verified`, `name`, and `groups` are injected. The claims constraint gets a first-class home in both the `id_token` and UserInfo instead of a hand-written endpoint.
- `TerminateSession` backs the logout decision.
- `NewProvider` takes an `IssuerFromRequest func(*http.Request) string`, so the per-tenant issuer `https://<host>/t/<tenantId>` is derived from the request rather than fought for.

Staleness is the other half of the argument. A library with no release in 19 months is a poor bet for the component whose whole job is to be specification-correct under attack; conformance and CVE fixes are not flowing. Fosite's tail is also the wrong shape for this service: `github.com/ory/x` drags in gobuffalo/pop, grpc-gateway, zipkin, logrus, ristretto, and golang/mock, into a service whose entire current dependency list is 14 modules. `go-jose` and `golang.org/x/oauth2`, which `op` needs, are already present.

### What this costs

Not free, and the costs are known going in:

- **`op` is an `http.Handler` (chi-based internally), not Echo handlers.** The OIDC surface mounts under the tenant prefix with `echo.WrapHandler` and will not look like `api/<domain>/<x>_handlers.go`. That is a real break from the repo's structure, confined to one mount point. The login UI, which we own, stays Echo.
- **`op.Storage` is one wide interface**, and the unused parts still need method bodies. Device authorization, token exchange, JWT profile, and client credentials are separate optional interfaces and stay unimplemented, which is the point.
- **A 32-byte `CryptoKey`** in config, for the library's code encryption. New required env var, and losing it invalidates in-flight authorization codes.
- `SetUserinfoFromScopes` is deprecated with an empty body; `SetUserinfoFromRequest` is the live one.

Contain it as planned: one `internal/oidc` package owns the storage adapter and is the only place that imports `op`, so nothing outside sees the library's types.

This does not conflict with owning identity. `an` keeps its accounts, its storage, its signing keys, its multi-tenancy, and its existing API. What comes from the library is the specification-shaped part that has been attacked in the wild and where a subtle mistake is a vulnerability rather than a bug.

Conformance is the largest risk in this work. State, nonce, PKCE, code single-use, redirect URI exact matching, client authentication, and key rotation all have to be right.

### Naming

`/api/authenticate/code` already means the passwordless magic code. The OAuth authorization code is a different thing with the same word. The new domain is `oidc` throughout (`internal/oidc`, `api/oidc`) and the word "code" is never used unqualified in either.

## Groups

The `groups` claim is what makes this useful to the demarkus broker, whose per-world access predicate matches on `domains`, `groups`, and `emails`. Sourcing groups from `az` means role assignments there drive access without a new mechanism.

This is the one place the plan adds a runtime dependency `an` does not have today. `an` currently depends on nothing, which is what keeps the authn/authz split clean; a synchronous call to `az` at mint time makes `az` an availability dependency of signing in anywhere. Three mitigations, all in scope:

- The `groups` scope is opt-in per client. A client that does not request it never touches `az`, so an `az` outage cannot block logins that do not need groups.
- Memberships are cached per `(tenant, account)` with a short TTL, so an `az` blip does not become a login outage.
- On a cache miss with `az` unreachable, minting **fails**. It never mints empty groups. Empty groups fail closed at the broker and present to users as a permissions outage rather than an authentication one, so the error must propagate.

Two open questions worth settling before implementation:

- Whether groups are computed at token mint time or refreshed on renewal, which decides how quickly a role change takes effect downstream. The cache TTL above is the same question in another form; settle them together.
- Whether each consuming tenant is its own `an` tenant, or one `an` tenant with per-tenant grouping in `az`. The per-tenant issuer URL decided above makes the first option cheap, which is an argument for it.

## Signing keys

JWKS and rotation already exist, but `NewDefaultTokenizer` parses the key set once at startup, so rotating a key requires a restart. That was acceptable when consumers called the validate endpoint. With external relying parties caching JWKS and verifying locally, the issuer should be able to roll a key without a deploy. Reloading the key set is small and belongs in step 1.

## Sequencing

0. **Pick the library.** Done 2026-07-27: `zitadel/oidc/v3`, reasoning above.
1. **Discovery, `/authorize` with the login UI and browser session, `/token`, `/userinfo`, `/logout`, id_token minting**, with one hardcoded confidential client. No client registry yet. Includes the `name` migration and the key-set reload.
2. **Switch a real consumer.** The `mark-knowledge` operator console currently posts operator passwords to `/api/authenticate` and holds them in transit. Moving it to the code flow deletes that code and exercises the whole loop against a small, low-risk app before anything external depends on it.
3. **`groups` sourced from `az`**, with the opt-in scope and the cache.
4. **Client registry**, so consumers can be registered per tenant rather than hardcoded.

Step 2 is the important one. A local console is a far cheaper first consumer than a broker on a provisioned box, and it proves the flow end to end while the blast radius is one staff tool.

## Done when

A browser can sign in at `/t/<tenantId>/authorize`, a confidential client can exchange the code at `/token`, and the returned `id_token` verifies against the published JWKS and carries `sub` (the account id), `email`, `email_verified`, `groups`, and `name`. A second app sharing the issuer signs the same user in without a second prompt, and `/logout` ends that session. The `mark-knowledge` console authenticates through the flow and contains no password-handling code.

The failure-path tests below pass, and the OpenID Foundation conformance suite runs green against the basic OP profile. Conformance is an exit criterion, not a follow-up.

## Testing

Per this repo's convention, no mocks and real services: embedded PostgreSQL, a real HTTP client driving the flow end to end, and verification against the real JWKS endpoint.

`go-oidc` and `golang.org/x/oauth2` are **already dependencies**, pulled in for Google sign-in. The integration suite can therefore drive a genuine relying party: real code flow, real PKCE, real discovery, and an `id_token` verified by the same library an external consumer would use, with no browser and no mocks. That is the conformance test the claims constraint asks for, and it costs nothing new.

Worth explicit tests for the failure paths, since they are the security-relevant ones: reused authorization code, mismatched redirect URI, wrong client secret, tampered `state`, replayed `nonce`, expired code, PKCE verifier mismatch, refresh token reuse after rotation, and an `az` outage during a `groups` mint (which must fail, not mint empty).

## Related

- The consuming service's decision record lives in the `mark-knowledge` soul as ADR 0005 (identity built on `an` and `az`) and ADR 0003 (central identity).
