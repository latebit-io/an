CREATE TABLE tenants (
    id text PRIMARY KEY,
    name text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    modified timestamptz NOT NULL DEFAULT now()
);
