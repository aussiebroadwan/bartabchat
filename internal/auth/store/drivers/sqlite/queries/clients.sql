-- name: GetClientByID :one
SELECT *
FROM clients
WHERE id = ?
LIMIT 1;

-- name: CreateClient :exec
INSERT INTO clients (id, name, secret_hash, scopes, protected)
VALUES (?, ?, ?, ?, ?);

-- name: UpdateClientSecretHash :exec
UPDATE clients
SET secret_hash = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateClientScopes :exec
UPDATE clients
SET scopes = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateClientName :exec
UPDATE clients
SET name = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteClient :exec
DELETE FROM clients
WHERE id = ?;

-- name: CountClients :one
SELECT COUNT(*) FROM clients;

-- name: ListClients :many
SELECT *
FROM clients
ORDER BY created_at DESC;