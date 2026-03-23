package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
)

const (
	stateKeyPrefix = "oauth_state:"
	stateTokenLen  = 32
)

type IdentityProvider interface {
	GetAuthURL(state, verifier string) string
	ExchangeCode(ctx context.Context, code, verifier string) (*model.ProviderUser, error)
}

type UserLinker interface {
	LinkIdentityTx(ctx context.Context, provider string, pu *model.ProviderUser) (*model.User, bool, error)
}

type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, userID, clientID string, scopes []string) (*model.TokenPair, error)
}

type StateStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type oauthState struct {
	Provider string `json:"provider"`
	Verifier string `json:"verifier"`
}

type Service struct {
	providers  map[string]IdentityProvider
	userLinker UserLinker
	tokens     TokenIssuer
	stateStore StateStore
	stateTTL   time.Duration
	log        *zap.Logger
}

func New(
	providers map[string]IdentityProvider,
	userLinker UserLinker,
	tokens TokenIssuer,
	stateStore StateStore,
	stateTTL time.Duration,
	log *zap.Logger,
) *Service {
	return &Service{
		providers:  providers,
		userLinker: userLinker,
		tokens:     tokens,
		stateStore: stateStore,
		stateTTL:   stateTTL,
		log:        log,
	}
}

func (s *Service) InitiateOAUth(ctx context.Context, provider string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", domainerrors.ErrProviderNotSupported
	}

	state, err := crypto.GenerateRandomToken(stateTokenLen)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	verifier := oauth2.GenerateVerifier()

	data, err := json.Marshal(&oauthState{
		Provider: provider,
		Verifier: verifier,
	})
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}

	key := stateKeyPrefix + state
	if err := s.stateStore.Set(ctx, key, string(data), s.stateTTL); err != nil {
		return "", fmt.Errorf("save state: %w", err)
	}

	authURL := p.GetAuthURL(state, verifier)

	s.log.Info("oauth flow initiated",
		zap.String("provider", provider),
	)

	return authURL, nil
}

func (s *Service) HandleCallback(ctx context.Context, provider, code, state string) (*model.TokenPair, error) {
	saved, err := s.validateAndConsumeState(ctx, provider, state)
	if err != nil {
		return nil, err
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, domainerrors.ErrProviderNotSupported
	}

	providerUser, err := p.ExchangeCode(ctx, code, saved.Verifier)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	if !providerUser.EmailVerified {
		return nil, domainerrors.ErrProviderEmailNotVerified
	}

	providerUser.Email = strings.ToLower(strings.TrimSpace(providerUser.Email))

	user, created, err := s.userLinker.LinkIdentityTx(ctx, provider, providerUser)
	if err != nil {
		return nil, fmt.Errorf("find or create user: %w", err)
	}

	pair, err := s.tokens.IssueTokenPair(ctx, user.ID, "", nil)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	if created {
		s.log.Info("user auto-provisioned via federation",
			zap.String("provider", provider),
			zap.String("user_id", user.ID),
			zap.String("email", providerUser.Email),
		)
	}

	s.log.Info("federation callback processed",
		zap.String("provider", provider),
		zap.String("user_id", user.ID),
	)

	return pair, nil
}

func (s *Service) validateAndConsumeState(ctx context.Context, provider, state string) (*oauthState, error) {
	key := stateKeyPrefix + state
	data, err := s.stateStore.Get(ctx, key)
	if err != nil {
		if errors.Is(err, domainerrors.ErrKeyNotFound) {
			return nil, domainerrors.ErrInvalidOAuthState
		}
		return nil, fmt.Errorf("get state: %w", err)
	}

	if err := s.stateStore.Delete(ctx, key); err != nil {
		s.log.Error("failed to delete state", zap.Error(err))
	}

	var saved oauthState
	if err := json.Unmarshal([]byte(data), &saved); err != nil {
		return nil, fmt.Errorf("unmarshal data: %w", err)
	}
	if saved.Provider != provider {
		return nil, domainerrors.ErrInvalidOAuthState
	}

	return &saved, nil
}
