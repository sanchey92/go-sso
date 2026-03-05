package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (s *Storage) SaveToken(ctx context.Context, token *model.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (token_hash, user_id, client_id, family_id, scopes, expires_at)
              VALUES ($1, $2, $3, $4, $5, $6)
              RETURNING id, created_at`

	var clientID any
	if token.ClientID != "" {
		clientID = token.ClientID
	}
	err := s.pool.QueryRow(ctx, query,
		token.TokenHash,
		token.UserID,
		clientID,
		token.FamilyID,
		token.Scopes,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (s *Storage) GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	query := `SELECT id, token_hash, user_id, client_id, family_id, scopes, revoked, expires_at, created_at
              FROM refresh_tokens
              WHERE token_hash = $1`

	var rt model.RefreshToken
	var clientID *string

	err := s.pool.QueryRow(ctx, query, hash).Scan(
		&rt.ID,
		&rt.TokenHash,
		&rt.UserID,
		&clientID,
		&rt.FamilyID,
		&rt.Scopes,
		&rt.Revoked,
		&rt.ExpiresAt,
		&rt.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainerrors.ErrInvalidToken
		}
		return nil, fmt.Errorf("select refresh token by hash: %w", err)
	}

	if clientID != nil {
		rt.ClientID = *clientID
	}

	return &rt, nil
}

func (s *Storage) Revoke(ctx context.Context, id string) error {
	query := `UPDATE refresh_tokens 
              SET revoked = true 
              WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domainerrors.ErrInvalidToken
	}
	return nil
}

func (s *Storage) RevokeByFamilyID(ctx context.Context, familyID string) error {
	query := `UPDATE refresh_tokens 
              SET revoked = true 
              WHERE family_id = $1 AND revoked = false`

	_, err := s.pool.Exec(ctx, query, familyID)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}
