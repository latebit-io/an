CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    email text NOT NULL,
    client_id text NOT NULL,
    refresh_jti uuid NOT NULL,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    modified timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email, client_id)
);

CREATE INDEX sessions_expires_idx ON sessions (expires);
