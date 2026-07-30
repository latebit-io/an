-- Registered OIDC clients. One row per client per tenant, so a hosted box's
-- broker is its own client rather than sharing one with every other tenant:
-- a shared confidential client means one compromised box yields credentials
-- that authenticate as all of them, and revoking it locks out the fleet.
--
-- The environment-configured client is not in here. It stays configuration
-- because it is the deployment's own client, and a registry that had to be
-- seeded before the service could serve its first login would be a worse
-- bootstrap than an environment variable.
CREATE TABLE oidc_clients (
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    -- sha256 hex of the secret, never the secret. Returned once at creation
    -- and unrecoverable afterwards, matching how api keys and logon codes
    -- are held here.
    secret_hash text NOT NULL,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    -- Consent is deferred on the understanding that clients are first party.
    -- Stored rather than assumed so a future third-party client is refused
    -- instead of silently served without a consent screen that does not exist.
    first_party boolean NOT NULL DEFAULT true,
    name text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, client_id)
);

-- Client ids are issued by us and are unique across tenants, but every lookup
-- carries a tenant: an id resolved without one would let a client registered
-- in one tenant authenticate against another.
CREATE INDEX oidc_clients_tenant ON oidc_clients (tenant_id);
