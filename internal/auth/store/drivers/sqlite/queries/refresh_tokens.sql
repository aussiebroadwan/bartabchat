-- Create a new refresh token for a user+client.
-- (token_hash is unique; scopes is the granted, space-delimited string)
-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, client_id, token_hash, session_id, scopes, amr, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- Fetch by token hash (for refresh flow).
-- Strict valid token lookup (not expired, not revoked).
-- name: GetRefreshTokenByHash :one
SELECT *
FROM refresh_tokens
WHERE token_hash = ?
  AND revoked = 0
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;

-- Mark a token as revoked (e.g., on logout or rotation).
-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = 1, updated_at = CURRENT_TIMESTAMP
WHERE token_hash = ?;

-- Bulk revoke all tokens for a user+client (e.g., when resetting credentials).
-- name: RevokeAllUserClientRefreshTokens :exec
UPDATE refresh_tokens
SET revoked = 1, updated_at = CURRENT_TIMESTAMP
WHERE user_id = ? AND client_id = ? AND revoked = 0;

-- Housekeeping: delete expired tokens (optional cron/maintenance).
-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at <= CURRENT_TIMESTAMP;
