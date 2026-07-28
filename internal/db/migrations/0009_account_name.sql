-- The OIDC id_token carries a name claim; accounts had no profile field.
-- Nullable: existing accounts have no name and the claim is omitted for them.
ALTER TABLE accounts ADD COLUMN name text;
