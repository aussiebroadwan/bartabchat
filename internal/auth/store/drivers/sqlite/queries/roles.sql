-- name: GetRoleByID :one
SELECT *
FROM roles
WHERE id = ?
LIMIT 1;

-- name: GetRoleByName :one
SELECT *
FROM roles
WHERE name = ?
LIMIT 1;

-- name: ListAllRoles :many
SELECT *
FROM roles
ORDER BY name ASC;

-- name: CreateRole :exec
INSERT INTO roles (id, name, scopes)
VALUES (?, ?, ?);

-- name: UpdateRoleScopes :exec
UPDATE roles
SET scopes = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteRole :exec
DELETE FROM roles
WHERE id = ?;

-- name: CountRoles :one
SELECT COUNT(*) FROM roles;
