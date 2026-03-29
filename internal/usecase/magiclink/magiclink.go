package magiclink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
)

const (
	magicKeyPrefix = "magic:"
	tokenLen       = 32
)

type UserGetter interface {
	GetByEmail(ctx context.Context, email string) (*model.User, error)
}

type CacheStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type LinkSender interface {
	SendMagicLinkEmail(ctx context.Context, toEmail, token string) error
}

type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, userID, clientID string, scopes []string) (*model.TokenPair, error)
}

type Service struct {
	users  UserGetter
	cache  CacheStore
	email  LinkSender
	tokens TokenIssuer
	ttl    time.Duration
	log    *zap.Logger
}

func New(
	users UserGetter,
	cache CacheStore,
	email LinkSender,
	tokens TokenIssuer,
	ttl time.Duration,
	log *zap.Logger,
) *Service {
	return &Service{
		users:  users,
		cache:  cache,
		email:  email,
		tokens: tokens,
		ttl:    ttl,
		log:    log,
	}
}

func (s *Service) RequestMagicLink(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			s.log.Info("magic link requested for non-existent email", zap.String("email", email))
			return nil
		}
		return fmt.Errorf("get user by email: %w", err)
	}
	if !user.EmailVerified {
		s.log.Info("magic link requested for unverified email", zap.String("email", email))
		return nil
	}

	token, err := crypto.GenerateRandomToken(tokenLen)
	if err != nil {
		s.log.Info("failed to generate magic link token", zap.Error(err))
		return nil
	}

	hash := crypto.HashToken(token)
	key := magicKeyPrefix + hash

	if err := s.cache.Set(ctx, key, user.ID, s.ttl); err != nil {
		s.log.Error("failed to cache magic link", zap.Error(err))
		return nil
	}

	if err := s.email.SendMagicLinkEmail(ctx, email, token); err != nil {
		s.log.Error("failed to send magic link email", zap.Error(err))
		return nil
	}

	return nil
}

func (s *Service) VerifyMagicLink(ctx context.Context, token string) (*model.TokenPair, error) {
	hash := crypto.HashToken(token)
	key := magicKeyPrefix + hash

	userID, err := s.cache.Get(ctx, key)
	if err != nil {
		if errors.Is(err, domainerrors.ErrKeyNotFound) {
			return nil, domainerrors.ErrMagicLinkNotFound
		}
		return nil, fmt.Errorf("get magic link: %w", err)
	}

	if err := s.cache.Delete(ctx, key); err != nil {
		s.log.Error("failed to delete magic link", zap.Error(err), zap.String("user_id", userID))
	}

	pair, err := s.tokens.IssueTokenPair(ctx, userID, "", nil)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	return pair, nil
}
