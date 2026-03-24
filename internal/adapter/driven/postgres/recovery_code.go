package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (s *Storage) SaveCodes(ctx context.Context, userID string, codeHashes []string) error {
	if len(codeHashes) == 0 {
		return nil
	}

	values := make([]string, 0, len(codeHashes))
	args := make([]any, 0, len(codeHashes)+1)
	args = append(args, userID) // $1

	for i, hash := range codeHashes {
		values = append(values, "($1, $"+strconv.Itoa(i+2)+")")
		args = append(args, hash)
	}

	query := fmt.Sprintf(
		`INSERT INTO recovery_codes (user_id, code_hash) VALUES %s`,
		strings.Join(values, ", "),
	)

	_, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert recovery codes: %w", err)
	}

	return nil
}

func (s *Storage) GetUnusedByUserID(ctx context.Context, userID string) ([]model.RecoveryCode, error) {
	query := `SELECT id, user_id, code_hash, used, created_at
              FROM recovery_codes
              WHERE user_id = $1 AND used = false
              ORDER BY created_at`

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query unused recovery codes: %w", err)
	}
	defer rows.Close()

	var codes []model.RecoveryCode
	for rows.Next() {
		var rc model.RecoveryCode
		if err := rows.Scan(&rc.ID, &rc.UserID, &rc.CodeHash, &rc.Used, &rc.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		codes = append(codes, rc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recovery code: %w", err)
	}

	return codes, nil
}

func (s *Storage) MarkUsed(ctx context.Context, id string) error {
	query := `UPDATE recovery_codes
              SET used = true
              WHERE id = $1 AND used = false`

	result, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mark recovery code used: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainerrors.ErrRecoveryCodeNotFound
	}
	return nil
}

func (s *Storage) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE from recovery_codes WHERE user_id = $1`

	_, err := s.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete recovery code: %w", err)
	}

	return nil
}
