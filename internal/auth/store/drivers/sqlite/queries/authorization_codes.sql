-- Store an issued authorization code (code_hash is a deterministic fingerprint).
-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (
    id,
    user_id,
    client_id,
    code_hash,
    redirect_uri,
    scopes,
    session_id,
    amr,
    code_challenge,
    code_challenge_method,
    mfa_session_id,
    expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- Lookup an authorization code for redemption if still valid.
-- name: GetAuthorizationCodeByHash :one
SELECT
    id,
    user_id,
    client_id,
    code_hash,
    redirect_uri,
    scopes,
    session_id,
    amr,
    code_challenge,
    code_challenge_method,
    mfa_session_id,
    expires_at,
    used_at,
    created_at
FROM authorization_codes
WHERE code_hash = ?
  AND used_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;

-- Mark an authorization code as consumed.
-- name: MarkAuthorizationCodeUsed :exec
UPDATE authorization_codes
SET used_at = CURRENT_TIMESTAMP
WHERE id = ?
  AND used_at IS NULL;

-- Housekeeping: remove expired or used authorization codes.
-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes
WHERE expires_at <= CURRENT_TIMESTAMP
   OR used_at IS NOT NULL;