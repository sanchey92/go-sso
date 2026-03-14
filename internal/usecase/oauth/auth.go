package oauth

import (
	"context"
	"encoding/json"
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
	authCodeKeyPrefix = "auth_code:"
	authCodeLen       = 32
)

type ClientGetter interface {
	GetClientByID(ctx context.Context, id string) (*model.OAuthClient, error)
}

type ClientAuthenticator interface {
	VerifySecret(ctx context.Context, clientID, rawSecret string) (*model.OAuthClient, error)
}

type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, userID, clientID string, scopes []string) (*model.TokenPair, error)
}

type AuthCodeStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type Service struct {
	clients     ClientGetter
	clientAuth  ClientAuthenticator
	codeStore   AuthCodeStore
	tokenIssuer TokenIssuer
	authCodeTTL time.Duration
	log         *zap.Logger
}

func New(
	clients ClientGetter,
	clientAuth ClientAuthenticator,
	codeStore AuthCodeStore,
	tokenIssuer TokenIssuer,
	authCodeTTL time.Duration,
	log *zap.Logger,
) *Service {
	return &Service{
		clients:     clients,
		clientAuth:  clientAuth,
		codeStore:   codeStore,
		tokenIssuer: tokenIssuer,
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

func (s *Service) ExchangeCode(ctx context.Context, params *model.CodeExchangeRequest) (*model.TokenPair, error) {
	key := authCodeKeyPrefix + params.Code

	data, err := s.codeStore.Get(ctx, key)
	if err != nil {
		if errors.Is(err, domainerrors.ErrKeyNotFound) {
			return nil, domainerrors.ErrInvalidAuthorizationCode
		}
		return nil, fmt.Errorf("get auth code: %w", err)
	}

	if err := s.codeStore.Delete(ctx, key); err != nil {
		s.log.Error("failed to delete auth code", zap.Error(err))
	}

	var authCode model.AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, fmt.Errorf("unmarshal auth code: %w", err)
	}

	if authCode.ClientID != params.ClientID || authCode.RedirectURI != params.RedirectURI {
		return nil, domainerrors.ErrInvalidAuthorizationCode
	}

	if !crypto.VerifyPKCE(params.CodeVerifier, authCode.CodeChallenge) {
		return nil, domainerrors.ErrInvalidAuthorizationCode
	}

	client, err := s.clients.GetClientByID(ctx, params.ClientID)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	if client.IsConfidential {
		if params.ClientSecret == "" {
			return nil, domainerrors.ErrInvalidCredentials
		}
		if _, err := s.clientAuth.VerifySecret(ctx, params.ClientID, params.ClientSecret); err != nil {
			return nil, fmt.Errorf("verify client secret: %w", err)
		}
	}

	var scopes []string
	if authCode.Scope != "" {
		scopes = strings.Fields(authCode.Scope)
	}

	pair, err := s.tokenIssuer.IssueTokenPair(ctx, authCode.UserID, params.ClientID, scopes)
	if err != nil {
		return nil, fmt.Errorf("issue code: %w", err)
	}

	s.log.Info("authorization code exchanged",
		zap.String("client_id", params.ClientID),
		zap.String("user_id", authCode.UserID),
	)

	return pair, nil
}

func containsURI(uris []string, target string) bool {
	for _, uri := range uris {
		if uri == target {
			return true
		}
	}
	return false
}
