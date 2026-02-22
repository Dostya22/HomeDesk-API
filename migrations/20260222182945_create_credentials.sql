CREATE TYPE secret_type AS ENUM ('password', 'ssh_key');

CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    kind secret_type NOT NULL DEFAULT 'password',
    encrypted_secret BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);