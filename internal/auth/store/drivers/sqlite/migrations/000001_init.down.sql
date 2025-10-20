
-- Drop tables in reverse order to respect foreign key constraints

-- Drop signing keys table and all related indices
DROP INDEX IF EXISTS idx_signing_keys_active;
DROP INDEX IF EXISTS idx_signing_keys_expires_at;
DROP INDEX IF EXISTS idx_signing_keys_retired_at;
DROP INDEX IF EXISTS idx_signing_keys_algorithm;
DROP INDEX IF EXISTS idx_signing_keys_kid;
DROP TABLE IF EXISTS signing_keys;

-- Drop authorization_codes table and its indexes
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;
DROP INDEX IF EXISTS idx_authorization_codes_code_hash;
DROP TABLE IF EXISTS authorization_codes;

-- Drop invites table and its indexes
DROP INDEX IF EXISTS idx_invites_client_used;
DROP INDEX IF EXISTS idx_invites_expires_at;
DROP INDEX IF EXISTS idx_invites_role_id;
DROP INDEX IF EXISTS idx_invites_client_id;
DROP INDEX IF EXISTS idx_invites_token_hash;
DROP TABLE IF EXISTS invites;

-- Drop mfa_sessions table and its indexes
DROP INDEX IF EXISTS idx_mfa_sessions_user_id;
DROP INDEX IF EXISTS idx_mfa_sessions_expires_at;
DROP TABLE IF EXISTS mfa_sessions;

-- Drop backup_codes table and its indexes
DROP INDEX IF EXISTS idx_backup_codes_user_id;
DROP TABLE IF EXISTS backup_codes;

-- Drop refresh_tokens table and its indexes
DROP INDEX IF EXISTS idx_refresh_session_id;
DROP INDEX IF EXISTS idx_refresh_expires_at;
DROP INDEX IF EXISTS idx_refresh_user_client;
DROP TABLE IF EXISTS refresh_tokens;

-- Drop clients table and its indexes
DROP INDEX IF EXISTS idx_clients_id;
DROP TABLE IF EXISTS clients;

-- Drop users table and its indexes
DROP INDEX IF EXISTS idx_users_role_id;
DROP INDEX IF EXISTS idx_users_username;
DROP TABLE IF EXISTS users;

-- Drop roles table and its indexes (last, since users reference it)
DROP INDEX IF EXISTS idx_roles_name;
DROP TABLE IF EXISTS roles;
