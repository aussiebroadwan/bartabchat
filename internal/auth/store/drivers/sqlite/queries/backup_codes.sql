-- name: CreateBackupCode :exec
INSERT INTO backup_codes (user_id, code_hash)
VALUES (?, ?);

-- name: GetBackupCodeHash :one
SELECT code_hash
FROM backup_codes
WHERE user_id = ? AND code_hash = ?
LIMIT 1;

-- name: DeleteBackupCode :exec
DELETE FROM backup_codes
WHERE user_id = ? AND code_hash = ?;

-- name: DeleteAllBackupCodes :exec
DELETE FROM backup_codes
WHERE user_id = ?;

-- name: CountUserBackupCodes :one
SELECT COUNT(*)
FROM backup_codes
WHERE user_id = ?;
