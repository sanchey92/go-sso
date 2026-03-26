package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type UserGetter interface {
	GetByEmail(ctx context.Context, email string) (*model.User, error)
}

type PasswordVerifier interface {
	Verify(password, encodedHash string) (bool, error)
}

type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, userID, clientID string, scopes []string) (*model.TokenPair, error)
}

type MFAChallengeIssuer interface {
	IssueMFAChallenge(ctx context.Context, userID string) (*model.MFAChallenge, error)
}

type Service struct {
	userRepo  UserGetter
	hasher    PasswordVerifier
	tokenSvc  TokenIssuer
	mfaIssuer MFAChallengeIssuer
	log       *zap.Logger
}

func New(ur UserGetter, h PasswordVerifier, ts TokenIssuer, mfaIssuer MFAChallengeIssuer, log *zap.Logger) *Service {
	return &Service{
		userRepo:  ur,
		hasher:    h,
		tokenSvc:  ts,
		mfaIssuer: mfaIssuer,
		log:       log,
	}
}

func (s *Service) Login(ctx context.Context, email, password string) (*model.LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			return nil, domainerrors.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	match, err := s.hasher.Verify(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return nil, domainerrors.ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, domainerrors.ErrEmailNotVerified
	}

	if user.Status != model.UserStatusActive {
		return nil, domainerrors.ErrInvalidCredentials
	}

	if user.MFAEnabled {
		challenge, err := s.mfaIssuer.IssueMFAChallenge(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("issue mfa challenge: %w", err)
		}
		s.log.Info("mfa challenge issued for login", zap.String("user_id", user.ID))
		return &model.LoginResult{MFAChallenge: challenge}, nil
	}

	pair, err := s.tokenSvc.IssueTokenPair(ctx, user.ID, "", nil)
	if err != nil {
		return nil, fmt.Errorf("issue token pair: %w", err)
	}

	s.log.Info("user logged in", zap.String("user_id", user.ID))

	return &model.LoginResult{Tokens: pair}, nil
}
