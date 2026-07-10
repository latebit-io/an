CREATE TABLE failed_attempts (
    tenant_id text NOT NULL,
    email text NOT NULL,
    count int NOT NULL DEFAULT 0,
    locked_until timestamptz,
    modified timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, email)
);
