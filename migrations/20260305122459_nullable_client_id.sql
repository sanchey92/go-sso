-- +goose Up
ALTER TABLE refresh_tokens ALTER COLUMN client_id DROP NOT NULL;

-- +goose Down
ALTER TABLE refresh_tokens ALTER COLUMN client_id SET NOT NULL;