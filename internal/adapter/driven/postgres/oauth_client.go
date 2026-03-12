package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (s *Storage) CreateClient(ctx context.Context, c *model.OAuthClient) error {
	query := `INSERT INTO oauth_clients (secret_hash, name, redirect_uris, allowed_scopes, is_confidential)
	          VALUES ($1, $2, $3, $4, $5)
			  RETURNING id, created_at`

	err := s.pool.QueryRow(ctx, query,
		c.SecretHash,
		c.Name,
		c.RedirectURIs,
		c.AllowedScopes,
		c.IsConfidential,
	).Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert oauth client: %w", err)
	}
	return nil
}

func (s *Storage) GetClientByID(ctx context.Context, id string) (*model.OAuthClient, error) {
	query := `SELECT id, secret_hash, name, redirect_uris, allowed_scopes, is_confidential, created_at
              FROM oauth_clients
              WHERE id = $1`

	var client model.OAuthClient
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&client.ID,
		&client.SecretHash,
		&client.Name,
		&client.RedirectURIs,
		&client.AllowedScopes,
		&client.IsConfidential,
		&client.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainerrors.ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("select oauth client by id: %w", err)
	}
	return &client, nil
}
