-- name: CreateRefreshToken :one
INSERT INTO tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    now(),
    now(),
    $2,
    $3,
    NULL
)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM tokens
WHERE token = $1;

-- name: RevokeRefreshToken :exec
UPDATE tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1;