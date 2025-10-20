-- Mint a new invite (token is stored as SHA-256 fingerprint).
-- name: CreateInvite :exec
INSERT INTO invites (id, token_hash, client_id, created_by, role_id, expires_at, reusable)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- Lookup invite for redemption:
--  - matches token hash
--  - not used
--  - not expired
-- name: GetActiveInviteByTokenHash :one
SELECT *
FROM invites
WHERE token_hash = ?
  AND used = 0
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;

-- Mark invite used by a specific user.
-- name: MarkInviteUsed :exec
UPDATE invites
SET used = 1,
    used_by = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
  AND used = 0;

-- Housekeeping: delete expired invites (optional cleanup).
-- name: DeleteExpiredInvites :exec
DELETE FROM invites
WHERE expires_at <= CURRENT_TIMESTAMP;