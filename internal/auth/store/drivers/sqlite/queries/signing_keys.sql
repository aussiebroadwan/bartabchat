-- name: CreateSigningKey :exec
INSERT INTO signing_keys (id, kid, algorithm, private_key_encrypted, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSigningKeyByKid :one
SELECT *
FROM signing_keys
WHERE kid = ?
LIMIT 1;

-- name: ListActiveSigningKeys :many
SELECT *
FROM signing_keys
WHERE retired_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
ORDER BY created_at DESC;

-- name: ListAllSigningKeys :many
SELECT *
FROM signing_keys
ORDER BY created_at DESC;

-- name: RetireSigningKey :exec
UPDATE signing_keys
SET retired_at = CURRENT_TIMESTAMP
WHERE kid = ?
  AND retired_at IS NULL;

-- name: DeleteExpiredSigningKeys :exec
DELETE FROM signing_keys
WHERE expires_at < CURRENT_TIMESTAMP;
