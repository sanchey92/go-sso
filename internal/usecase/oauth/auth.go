package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
)

const (
	authCodeKeyPrefix = "auth_code:"
	authCodeLen       = 32
)

type ClientGetter interface {
	GetClientByID(ctx context.Context, id string) (*model.OAuthClient, error)
}

type AuthCodeStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type Service struct {
	clients     ClientGetter
	codeStore   AuthCodeStore
	authCodeTTL time.Duration
	log         *zap.Logger
}

func New(clients ClientGetter, codeStore AuthCodeStore, authCodeTTL time.Duration, log *zap.Logger) *Service {
	return &Service{
		clients:     clients,
		codeStore:   codeStore,
		authCodeTTL: authCodeTTL,
		log:         log,
	}
}

func (s *Service) Authorize(ctx context.Context, params *model.AuthorizationCode) (string, error) {
	client, err := s.clients.GetClientByID(ctx, params.ClientID)
	if err != nil {
		return "", fmt.Errorf("get client: %w", err)
	}

	if !containsURI(client.RedirectURIs, params.RedirectURI) {
		return "", domainerrors.ErrInvalidRedirectURI
	}

	code, err := crypto.GenerateRandomToken(authCodeLen)
	if err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}

	data, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("marshal auth code data: %w", err)
	}

	key := authCodeKeyPrefix + code
	if err := s.codeStore.Set(ctx, key, string(data), s.authCodeTTL); err != nil {
		return "", fmt.Errorf("save auth code: %w", err)
	}

	s.log.Info("authorization code issued",
		zap.String("client_id", params.ClientID),
		zap.String("user_id", params.UserID),
	)

	return code, nil
}

func containsURI(uris []string, target string) bool {
	for _, uri := range uris {
		if uri == target {
			return true
		}
	}
	return false
}
