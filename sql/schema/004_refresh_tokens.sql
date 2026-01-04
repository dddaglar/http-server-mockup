-- +goose Up
CREATE TABLE tokens (
    token TEXT PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL
);

-- +goose Down
DROP TABLE tokens;
