-- Roles define sets of scopes that users can request. This implements RBAC
-- to prevent privilege escalation where users could request admin scopes by
-- knowing a high-privilege client ID.
CREATE TABLE IF NOT EXISTS roles (
    id              TEXT PRIMARY KEY,                   -- ULID
    name            TEXT UNIQUE NOT NULL,               -- e.g., "admin", "user", "readonly"
    scopes          TEXT NOT NULL,                      -- space-delimited scope capabilities
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

-- Users are a store for end users of the system, these can be authenticated
-- via username/password.
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,                   -- ULID
    username        TEXT UNIQUE NOT NULL,               -- Login name
    preferred_name  TEXT UNIQUE NOT NULL,               -- Preferred name
    password_hash   TEXT NOT NULL,                      -- argon2 base64 hash
    role_id         TEXT NOT NULL REFERENCES roles(id), -- User's role (determines allowed scopes)
    mfa_enabled     TIMESTAMP DEFAULT NULL,             -- Timestamp when MFA was enabled
    mfa_secret      TEXT DEFAULT NULL,                  -- TOTP secret (base32 encoded)
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);

-- Clients are software applications or services that act on behalf of users for
-- example a frontend client or bot service. Might need to add a redirect_uri
-- field later for OAuth2 flows.
CREATE TABLE IF NOT EXISTS clients (
    id              TEXT PRIMARY KEY,       -- ULID
    name            TEXT NOT NULL,          -- Human-readable name of the client
    secret_hash     TEXT DEFAULT NULL,      -- argon2 base64 hash (only for confidential clients)
    scopes          TEXT NOT NULL,          -- space-delimited scope capabilities of the client, e.g. "chat:read chat:write"
    protected       BOOLEAN NOT NULL DEFAULT FALSE, -- if true, cannot be deleted (e.g., bootstrap client)
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_id ON clients(id);

-- Refresh tokens are long-lived credentials used to obtain new access tokens.
-- They are tied to a specific user-client pair and can be revoked if compromised.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              TEXT PRIMARY KEY,            -- ULID
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    token_hash      TEXT UNIQUE NOT NULL,        -- argon2 base64 hash
    session_id      TEXT NOT NULL,               -- Session ID that persists across token refreshes
    scopes          TEXT NOT NULL,               -- space-delimited scope granted by the user (space-delimited)
    amr             TEXT NOT NULL,               -- Authentication Method Reference history (space-delimited)
    expires_at      TIMESTAMP NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refresh_user_client ON refresh_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_session_id ON refresh_tokens(session_id);

-- Invites are tokens that allow new users to join for a specific client.
-- They are created by admins, can expire, and track which user redeemed them.
-- Invites can be single-use or reusable, and specify the role for invited users.
CREATE TABLE IF NOT EXISTS invites (
    id              TEXT PRIMARY KEY,                       -- ULID
    token_hash      TEXT UNIQUE NOT NULL,                   -- SHA-256 fingerprint
    client_id       TEXT NOT NULL,                          -- OAuth2 client identifier
    created_by      TEXT NOT NULL REFERENCES users(id),     -- admin who created it
    role_id         TEXT NOT NULL REFERENCES roles(id),     -- role to assign to invited user
    expires_at      TIMESTAMP NOT NULL,
    reusable        BOOLEAN NOT NULL DEFAULT FALSE,         -- can be used multiple times
    used            BOOLEAN NOT NULL DEFAULT FALSE,         -- has been redeemed (for single-use invites)
    used_by         TEXT REFERENCES users(id),              -- user who redeemed it (NULL until used)
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invites_token_hash ON invites(token_hash);
CREATE INDEX IF NOT EXISTS idx_invites_client_id ON invites(client_id);
CREATE INDEX IF NOT EXISTS idx_invites_role_id ON invites(role_id);
CREATE INDEX IF NOT EXISTS idx_invites_expires_at ON invites(expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_client_used ON invites(client_id, used);

-- Backup codes are one-time use recovery codes for MFA.
-- They are stored as SHA-256 fingerprints and deleted after use.
CREATE TABLE IF NOT EXISTS backup_codes (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,                      -- SHA-256 fingerprint
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id ON backup_codes(user_id);

-- MFA sessions are temporary sessions created during MFA authentication flow.
-- When a user with MFA enabled authenticates, an MFA session is created and they
-- must complete the MFA challenge to receive tokens.
CREATE TABLE IF NOT EXISTS mfa_sessions (
    id              TEXT PRIMARY KEY,                       -- ULID (the mfa_token)
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes          TEXT NOT NULL,                          -- space-delimited requested scopes
    amr             TEXT NOT NULL,                          -- authentication method references (e.g., "pwd")
    session_id      TEXT NOT NULL,                          -- session ID for future refresh token
    attempts        INTEGER NOT NULL DEFAULT 0,             -- failed MFA attempts (max 5 to prevent brute force)
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL                      -- short-lived (5 minutes recommended)
);

CREATE INDEX IF NOT EXISTS idx_mfa_sessions_expires_at ON mfa_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_sessions_user_id ON mfa_sessions(user_id);


-- Authorization codes issued during the OAuth 2.0 authorization_code flow.
CREATE TABLE IF NOT EXISTS authorization_codes (
    id                     TEXT PRIMARY KEY,                                   -- ULID
    user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id              TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    code_hash              TEXT NOT NULL UNIQUE,                               -- SHA-256/argon2 fingerprint
    redirect_uri           TEXT NOT NULL,
    scopes                 TEXT NOT NULL,                                      -- space-delimited scopes
    session_id             TEXT NOT NULL,                                      -- OAuth session identifier
    amr                    TEXT NOT NULL,                                      -- space-delimited AMR values
    code_challenge         TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL,
    mfa_session_id         TEXT DEFAULT NULL REFERENCES mfa_sessions(id) ON DELETE SET NULL,
    expires_at             TIMESTAMP NOT NULL,
    used_at                TIMESTAMP DEFAULT NULL,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_code_hash ON authorization_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);


-- Signing keys are used for JWT token signing with support for key rotation.
-- Keys are encrypted at rest and can be marked as retired while remaining valid
-- for verification during a grace period.
CREATE TABLE IF NOT EXISTS signing_keys (
    id                    TEXT PRIMARY KEY,                   -- ULID
    kid                   TEXT UNIQUE NOT NULL,               -- Key identifier in JWKS (e.g., "bartab-abc123")
    algorithm             TEXT NOT NULL,                      -- RS256, ES256, or EdDSA
    private_key_encrypted BLOB NOT NULL,                      -- AES-256-GCM encrypted private key PEM
    created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at            TIMESTAMP DEFAULT NULL,             -- When key was retired from active signing (NULL = active)
    expires_at            TIMESTAMP NOT NULL                  -- Hard deletion after this (for cleanup)
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_kid ON signing_keys(kid);
CREATE INDEX IF NOT EXISTS idx_signing_keys_algorithm ON signing_keys(algorithm);
CREATE INDEX IF NOT EXISTS idx_signing_keys_retired_at ON signing_keys(retired_at);
CREATE INDEX IF NOT EXISTS idx_signing_keys_expires_at ON signing_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys(retired_at, expires_at) WHERE retired_at IS NULL;
