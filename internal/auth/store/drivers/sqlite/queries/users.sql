-- name: GetUserByID :one
SELECT *
FROM users
WHERE id = ?
LIMIT 1;

-- name: GetUserByUsername :one
SELECT *
FROM users
WHERE username = ?
LIMIT 1;

-- name: CreateUser :exec
INSERT INTO users (id, username, preferred_name, password_hash, role_id)
VALUES (?, ?, ?, ?, ?);

-- name: UpdateUserPreferredName :exec
UPDATE users
SET preferred_name = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateUserPasswordHash :exec
UPDATE users
SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;


-- name: DeleteUser :exec
DELETE FROM users
WHERE id = ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: UpdateUserMFASecret :exec
UPDATE users
SET mfa_secret = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: EnableUserMFA :exec
UPDATE users
SET mfa_enabled = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DisableUserMFA :exec
UPDATE users
SET mfa_enabled = NULL, mfa_secret = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: GetUserMFAInfo :one
SELECT id, mfa_enabled, mfa_secret
FROM users
WHERE id = ?
LIMIT 1;