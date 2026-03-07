package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (s *Storage) Create(ctx context.Context, user *model.User) error {
	query := `INSERT INTO users(email, password_hash, email_verified, mfa_enabled, status)
              VALUES ($1, $2, $3, $4, $5)
              RETURNING id, created_at, updated_at`

	err := s.pool.QueryRow(ctx, query,
		user.Email,
		user.PasswordHash,
		user.EmailVerified,
		user.MFAEnabled,
		string(user.Status),
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return domainerrors.ErrEmailAlreadyExists
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *Storage) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, password_hash, email_verified, mfa_enabled, 
              mfa_secret_enc, status, created_at, updated_at
              FROM users
              WHERE email = $1`

	var user model.User
	var status string

	err := s.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.MFAEnabled,
		&user.MFASecretEnc,
		&status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainerrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("select user by email: %w", err)
	}

	user.Status = model.UserStatus(status)
	return &user, nil
}

func (s *Storage) UpdateEmailVerified(ctx context.Context, userID string, verified bool) error {
	query := `UPDATE users
	          SET email_verified = $1, updated_at = now()
			  WHERE id = $2`

	result, err := s.pool.Exec(ctx, query, verified, userID)
	if err != nil {
		return fmt.Errorf("update email_verified: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainerrors.ErrUserNotFound
	}
	return nil
}

func (s *Storage) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	query := `UPDATE users
              SET password_hash = $2, updated_at = now()
              WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainerrors.ErrUserNotFound
	}
	return nil
}
