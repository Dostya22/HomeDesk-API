CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    -- Identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    -- Stored as an Argon2id hash string
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    -- The Public Key (Plaintext) used by others to share Team Keys with this user
    public_key BYTEA NOT NULL,
    -- The Private Key (Encrypted) so the user can log in on multiple devices.
    encrypted_private_key BYTEA NOT NULL,
    private_key_nonce BYTEA NOT NULL,
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Keep updated_at current
CREATE OR REPLACE FUNCTION update_modified_column()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_user_modtime
    BEFORE UPDATE ON users
    FOR EACH ROW
EXECUTE PROCEDURE update_modified_column();