CREATE TABLE logon_codes (
    tenant_id text NOT NULL,
    email text NOT NULL,
    code_hash text NOT NULL,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, email)
);
