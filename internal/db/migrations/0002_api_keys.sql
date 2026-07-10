CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    prefix text NOT NULL UNIQUE,
    hash text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
