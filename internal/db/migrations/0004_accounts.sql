CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    verified boolean NOT NULL DEFAULT false,
    verification_hash text,
    enabled boolean NOT NULL DEFAULT true,
    deleted boolean NOT NULL DEFAULT false,
    created timestamptz NOT NULL DEFAULT now(),
    modified timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE social_logins (
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    provider text NOT NULL,
    subject text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, provider),
    UNIQUE (provider, subject)
);
