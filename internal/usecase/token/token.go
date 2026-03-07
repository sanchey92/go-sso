package token

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
)

const defaultAudience = "sso"

type TokenGenerator interface {
	GenerateToken(userID, audience string) (string, error)
	GenerateRefreshToken() (raw, hash string, err error)
}

type RefreshTokenRepository interface {
	SaveToken(ctx context.Context, token *model.RefreshToken) error
	GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeByFamilyID(ctx context.Context, familyID string) error
}

type Service struct {
	tokenGen    TokenGenerator
	refreshRepo RefreshTokenRepository
	accessTTL   time.Duration
	refreshTTL  time.Duration
	log         *zap.Logger
}

func New(tg TokenGenerator, rr RefreshTokenRepository, accessTTL, refreshTTL time.Duration, log *zap.Logger) *Service {
	return &Service{
		tokenGen:    tg,
		refreshRepo: rr,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
		log:         log,
	}
}

func (s *Service) IssueTokenPair(ctx context.Context, userID, clientID string, scopes []string) (*model.TokenPair, error) {
	accessToken, err := s.tokenGen.GenerateToken(userID, defaultAudience)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	familyID, err := crypto.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("generate family id: %w", err)
	}

	refreshToken, err := s.saveRefreshToken(ctx, userID, familyID, clientID, scopes)
	if err != nil {
		return nil, err
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *Service) RefreshTokens(ctx context.Context, rawRefreshToken string) (*model.TokenPair, error) {
	tokenHash := crypto.HashToken(rawRefreshToken)

	stored, err := s.refreshRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, domainerrors.ErrTokenExpired
	}

	if stored.Revoked {
		if revokeErr := s.refreshRepo.RevokeByFamilyID(ctx, stored.FamilyID); revokeErr != nil {
			return nil, fmt.Errorf("revoke token family: %w", revokeErr)
		}
		s.log.Warn("refresh token replay detected",
			zap.String("family_id", stored.FamilyID),
			zap.String("user_id", stored.UserID),
		)
		return nil, domainerrors.ErrTokenRevoked
	}

	if err = s.refreshRepo.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoke current token: %w", err)
	}

	newAccessToken, err := s.tokenGen.GenerateToken(stored.UserID, defaultAudience)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	newRefreshToken, err := s.saveRefreshToken(ctx, stored.UserID, stored.FamilyID, stored.ClientID, stored.Scopes)
	if err != nil {
		return nil, err
	}

	s.log.Info("tokens refreshed",
		zap.String("user_id", stored.UserID),
		zap.String("family_id", stored.FamilyID),
	)

	return &model.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *Service) RevokeToken(ctx context.Context, rawToken string) error {
	tokenHash := crypto.HashToken(rawToken)

	stored, err := s.refreshRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("get refresh token: %w", err)
	}
	if stored.Revoked {
		return nil
	}

	if err := s.refreshRepo.Revoke(ctx, stored.ID); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	s.log.Info("token revoked", zap.String("user_id", stored.UserID))
	return nil
}

func (s *Service) saveRefreshToken(ctx context.Context, userID, familyID, clientID string, scopes []string) (string, error) {
	raw, hash, err := s.tokenGen.GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}

	rt := &model.RefreshToken{
		TokenHash: hash,
		UserID:    userID,
		FamilyID:  familyID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}
	if err = s.refreshRepo.SaveToken(ctx, rt); err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}

	return raw, nil
}
