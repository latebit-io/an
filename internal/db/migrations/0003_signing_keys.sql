CREATE TABLE signing_keys (
    id uuid PRIMARY KEY,
    algorithm text NOT NULL DEFAULT 'RS256',
    private_key_pem text NOT NULL,
    public_key_pem text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
