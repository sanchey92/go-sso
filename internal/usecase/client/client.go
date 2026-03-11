package client

import (
	"context"
	"fmt"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	secretLength = 32
	bcryptCost   = bcrypt.DefaultCost
)

type OAuthRepository interface {
	Create(ctx context.Context, client *model.OAuthClient) error
	GetByID(ctx context.Context, id string) (*model.OAuthClient, error)
}

type Service struct {
	repo OAuthRepository
	log  *zap.Logger
}

func New(repo OAuthRepository, log *zap.Logger) *Service {
	return &Service{
		repo: repo,
		log:  log,
	}
}

func (s *Service) Create(
	ctx context.Context,
	name string, redirectURIs,
	allowedScopes []string,
	isConfidential bool,
) (*model.OAuthClient, string, error) {
	rawSecret, err := crypto.GenerateRandomToken(secretLength)
	if err != nil {
		return nil, "", fmt.Errorf("generate client secret: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcryptCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash client secret: %w", err)
	}

	client := &model.OAuthClient{
		SecretHash:     string(hash),
		Name:           name,
		RedirectURIs:   redirectURIs,
		AllowedScopes:  allowedScopes,
		IsConfidential: isConfidential,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		return nil, "", fmt.Errorf("create oauth client: %w", err)
	}

	s.log.Info("oauth client created",
		zap.String("client_id", client.ID),
		zap.String("name", name),
	)

	return client, rawSecret, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*model.OAuthClient, error) {
	client, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get oauth client")
	}
	return client, nil
}

func (s *Service) VerifySecret(ctx context.Context, clientID, rawSecret string) (*model.OAuthClient, error) {
	client, err := s.repo.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get oauth client: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(rawSecret)); err != nil {
		return nil, domainerrors.ErrInvalidCredentials
	}

	return client, nil
}
