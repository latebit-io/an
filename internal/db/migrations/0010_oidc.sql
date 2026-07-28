-- The OIDC provider surface. Separate from sessions: an OIDC grant is one
-- row per issued grant, so the same account signed in from two browsers
-- keeps two live grants, where sessions is one row per (tenant, email,
-- client) by design.

-- An authorization request, live from /authorize until the code is
-- exchanged at /token. subject is empty until the login UI authenticates
-- the user; done flips at the same moment. The code is high entropy and
-- hashed at rest like every other such token here.
CREATE TABLE oidc_auth_requests (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL DEFAULT '',
    redirect_uri text NOT NULL,
    response_type text NOT NULL,
    response_mode text NOT NULL DEFAULT '',
    scopes text[] NOT NULL DEFAULT '{}',
    state text NOT NULL DEFAULT '',
    nonce text NOT NULL DEFAULT '',
    code_challenge text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    code_hash text UNIQUE,
    amr text[] NOT NULL DEFAULT '{}',
    auth_time timestamptz,
    done boolean NOT NULL DEFAULT false,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    modified timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_auth_requests_expires_idx ON oidc_auth_requests (expires);

-- Refresh tokens are the grant record. No unique constraint on
-- (tenant_id, subject, client_id): concurrent grants are expected.
CREATE TABLE oidc_refresh_tokens (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    audience text[] NOT NULL DEFAULT '{}',
    scopes text[] NOT NULL DEFAULT '{}',
    amr text[] NOT NULL DEFAULT '{}',
    auth_time timestamptz NOT NULL,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_refresh_tokens_expires_idx ON oidc_refresh_tokens (expires);
CREATE INDEX oidc_refresh_tokens_subject_idx ON oidc_refresh_tokens (tenant_id, subject, client_id);

-- Access tokens on this surface are opaque: the id is the credential the
-- library hands out (encrypted), so there is nothing to hash here.
CREATE TABLE oidc_access_tokens (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    audience text[] NOT NULL DEFAULT '{}',
    scopes text[] NOT NULL DEFAULT '{}',
    refresh_token_id uuid REFERENCES oidc_refresh_tokens (id) ON DELETE CASCADE,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_access_tokens_expires_idx ON oidc_access_tokens (expires);
CREATE INDEX oidc_access_tokens_subject_idx ON oidc_access_tokens (tenant_id, subject, client_id);

-- The IdP browser session behind single sign-on: the cookie an sets at
-- login, so a second /authorize from another client does not re-prompt.
CREATE TABLE oidc_browser_sessions (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    auth_time timestamptz NOT NULL,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_browser_sessions_expires_idx ON oidc_browser_sessions (expires);
CREATE INDEX oidc_browser_sessions_account_idx ON oidc_browser_sessions (tenant_id, account_id);
