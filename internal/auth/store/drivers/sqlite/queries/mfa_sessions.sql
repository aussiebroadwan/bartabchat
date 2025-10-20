-- name: CreateMFASession :exec
INSERT INTO mfa_sessions (id, user_id, client_id, scopes, amr, session_id, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetMFASession :one
SELECT *
FROM mfa_sessions
WHERE id = ? AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;

-- name: IncrementMFASessionAttempts :one
UPDATE mfa_sessions
SET attempts = attempts + 1
WHERE id = ? AND expires_at > CURRENT_TIMESTAMP
RETURNING *;

-- name: DeleteMFASession :exec
DELETE FROM mfa_sessions
WHERE id = ?;

-- name: DeleteExpiredMFASessions :exec
DELETE FROM mfa_sessions
WHERE expires_at <= CURRENT_TIMESTAMP;
