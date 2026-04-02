package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (s *Storage) LinkIdentityTx(
	ctx context.Context,
	provider string,
	pu *model.ProviderUser,
) (*model.User, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			s.log.Error("failed to rollback tx", zap.Error(err))
		}
	}()

	userID, err := findIdentityUserID(ctx, tx, provider, pu.ProviderUserID)
	if err == nil {
		user, err := fetchUserByID(ctx, tx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("get user by id: %w", err)
		}
		return user, false, nil
	}

	if !errors.Is(err, domainerrors.ErrFederatedIdentityNotFound) {
		return nil, false, fmt.Errorf("find identity: %w", err)
	}

	user, err := fetchUserByEmail(ctx, tx, pu.Email)

	created := false

	if err != nil {
		if !errors.Is(err, domainerrors.ErrUserNotFound) {
			return nil, false, fmt.Errorf("get user by email: %w", err)
		}

		user, err = insertUser(ctx, tx, pu)
		if err != nil {
			return nil, false, fmt.Errorf("create user: %w", err)
		}

		created = true
	}

	if err := insertIdentity(ctx, tx, user.ID, provider, pu); err != nil {
		return nil, false, fmt.Errorf("create identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit tx: %w", err)
	}

	return user, created, nil
}

func findIdentityUserID(ctx context.Context, tx pgx.Tx, provider, providerUserID string) (string, error) {
	var userID string

	err := tx.QueryRow(ctx,
		`SELECT user_id FROM federated_identities
		 WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", domainerrors.ErrFederatedIdentityNotFound
		}
		return "", fmt.Errorf("query federated identity: %w", err)
	}

	return userID, nil
}

func fetchUserByID(ctx context.Context, tx pgx.Tx, id string) (*model.User, error) {
	return scanUser(tx.QueryRow(ctx,
		`SELECT id, email, password_hash, email_verified, mfa_enabled,
		        mfa_secret_enc, status, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	))
}

func fetchUserByEmail(ctx context.Context, tx pgx.Tx, email string) (*model.User, error) {
	return scanUser(tx.QueryRow(ctx,
		`SELECT id, email, password_hash, email_verified, mfa_enabled,
		        mfa_secret_enc, status, created_at, updated_at
		 FROM users WHERE email = $1`, email,
	))
}

func insertUser(ctx context.Context, tx pgx.Tx, pu *model.ProviderUser) (*model.User, error) {
	user := &model.User{
		Email:         pu.Email,
		EmailVerified: true,
		Status:        model.UserStatusActive,
	}

	err := tx.QueryRow(ctx,
		`INSERT INTO users(email, password_hash, email_verified, mfa_enabled, status)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, created_at, updated_at`,
		user.Email, user.PasswordHash, user.EmailVerified, false, string(user.Status),
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, domainerrors.ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	return user, nil
}

func insertIdentity(ctx context.Context, tx pgx.Tx, userID, provider string, pu *model.ProviderUser) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO federated_identities (user_id, provider, provider_user_id, email, name, avatar_url)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, provider, pu.ProviderUserID, pu.Email, pu.Name, pu.AvatarURL,
	)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return domainerrors.ErrIdentityAlreadyLinked
		}
		return fmt.Errorf("insert identity: %w", err)
	}

	return nil
}

func (s *Storage) GetByProviderAndProviderUserID(
	ctx context.Context,
	provider, providerUserID string,
) (*model.FederatedIdentity, error) {
	return scanFederatedIdentity(s.pool.QueryRow(ctx,
		`SELECT id, user_id, provider, provider_user_id, email, name, avatar_url,
		        created_at, updated_at
		 FROM federated_identities
		 WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	))
}

func (s *Storage) GetByUserID(ctx context.Context, userID string) ([]*model.FederatedIdentity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, provider, provider_user_id, email, name, avatar_url,
		        created_at, updated_at
		 FROM federated_identities
		 WHERE user_id = $1
		 ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("query federated identities: %w", err)
	}
	defer rows.Close()

	result := make([]*model.FederatedIdentity, 0)

	for rows.Next() {
		fi, err := scanFederatedIdentity(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, fi)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate federated identities: %w", err)
	}

	return result, nil
}

func scanFederatedIdentity(row pgx.Row) (*model.FederatedIdentity, error) {
	var fi model.FederatedIdentity

	err := row.Scan(
		&fi.ID,
		&fi.UserID,
		&fi.Provider,
		&fi.ProviderUserID,
		&fi.Email,
		&fi.Name,
		&fi.AvatarURL,
		&fi.CreatedAt,
		&fi.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainerrors.ErrFederatedIdentityNotFound
		}
		return nil, fmt.Errorf("scan federated identity: %w", err)
	}

	return &fi, nil
}
