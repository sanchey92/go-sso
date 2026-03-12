package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/client/mocks"
)

func TestService_Create(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name           string
		clientName     string
		redirectURIs   []string
		allowedScopes  []string
		isConfidential bool
		setupMock      func(repo *mocks.OAuthRepository)
		wantErr        string
		check          func(t *testing.T, clientID string, rawSecret string)
	}{
		{
			name:           "successful creation",
			clientName:     "My App",
			redirectURIs:   []string{"https://app.example.com/callback"},
			allowedScopes:  []string{"openid", "profile", "email"},
			isConfidential: true,
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					CreateClient(mock.Anything, mock.AnythingOfType("*model.OAuthClient")).
					Run(func(_ context.Context, c *model.OAuthClient) {
						c.ID = "generated-uuid"
						c.CreatedAt = time.Now()
					}).
					Return(nil)
			},
			check: func(t *testing.T, clientID string, rawSecret string) {
				assert.Equal(t, "generated-uuid", clientID)
				assert.NotEmpty(t, rawSecret)
			},
		},
		{
			name:           "repository error",
			clientName:     "Failing App",
			redirectURIs:   []string{"https://fail.example.com/callback"},
			allowedScopes:  []string{"openid"},
			isConfidential: false,
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					CreateClient(mock.Anything, mock.AnythingOfType("*model.OAuthClient")).
					Return(errors.New("db connection lost"))
			},
			wantErr: "create oauth client: db connection lost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewOAuthRepository(t)
			tt.setupMock(repo)

			svc := New(repo, zap.NewNop())

			clientID, rawSecret, err := svc.Create(ctx, tt.clientName, tt.redirectURIs, tt.allowedScopes, tt.isConfidential)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, clientID)
				assert.Empty(t, rawSecret)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, clientID)

			if tt.check != nil {
				tt.check(t, clientID, rawSecret)
			}
		})
	}
}

func TestService_GetByID(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		clientID  string
		setupMock func(repo *mocks.OAuthRepository)
		wantErr   string
		check     func(t *testing.T, client *model.OAuthClient)
	}{
		{
			name:     "found",
			clientID: "existing-client-id",
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "existing-client-id").
					Return(&model.OAuthClient{
						ID:             "existing-client-id",
						SecretHash:     "$2a$10$somehash",
						Name:           "Test App",
						RedirectURIs:   []string{"https://app.example.com/callback"},
						AllowedScopes:  []string{"openid"},
						IsConfidential: true,
					}, nil)
			},
			check: func(t *testing.T, client *model.OAuthClient) {
				assert.Equal(t, "existing-client-id", client.ID)
				assert.Equal(t, "Test App", client.Name)
				assert.NotEmpty(t, client.SecretHash, "SecretHash should be present in usecase response")
			},
		},
		{
			name:     "not found",
			clientID: "nonexistent-id",
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "nonexistent-id").
					Return(nil, domainerrors.ErrOAuthClientNotFound)
			},
			wantErr: domainerrors.ErrOAuthClientNotFound.Error(),
		},
		{
			name:     "repository error",
			clientID: "some-id",
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "some-id").
					Return(nil, errors.New("db timeout"))
			},
			wantErr: "get oauth client: db timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewOAuthRepository(t)
			tt.setupMock(repo)

			svc := New(repo, zap.NewNop())

			client, err := svc.GetByID(ctx, tt.clientID)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, client)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)

			if tt.check != nil {
				tt.check(t, client)
			}
		})
	}
}

func TestService_VerifySecret(t *testing.T) {
	ctx := t.Context()

	validSecret := "my-raw-secret"
	validHash, err := bcrypt.GenerateFromPassword([]byte(validSecret), bcrypt.MinCost)
	require.NoError(t, err)

	storedClient := &model.OAuthClient{
		ID:             "client-123",
		SecretHash:     string(validHash),
		Name:           "Secure App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		AllowedScopes:  []string{"openid", "profile"},
		IsConfidential: true,
	}

	tests := []struct {
		name      string
		clientID  string
		rawSecret string
		setupMock func(repo *mocks.OAuthRepository)
		wantErr   error
		check     func(t *testing.T, client *model.OAuthClient)
	}{
		{
			name:      "success",
			clientID:  "client-123",
			rawSecret: validSecret,
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(storedClient, nil)
			},
			check: func(t *testing.T, client *model.OAuthClient) {
				assert.Equal(t, "client-123", client.ID)
				assert.Equal(t, "Secure App", client.Name)
			},
		},
		{
			name:      "invalid secret",
			clientID:  "client-123",
			rawSecret: "wrong-secret",
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(storedClient, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials,
		},
		{
			name:      "client not found",
			clientID:  "nonexistent-id",
			rawSecret: validSecret,
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "nonexistent-id").
					Return(nil, domainerrors.ErrOAuthClientNotFound)
			},
			wantErr: domainerrors.ErrOAuthClientNotFound,
		},
		{
			name:      "repository error",
			clientID:  "client-123",
			rawSecret: validSecret,
			setupMock: func(repo *mocks.OAuthRepository) {
				repo.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(nil, errors.New("db timeout"))
			},
			wantErr: errors.New("get oauth client: db timeout"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewOAuthRepository(t)
			tt.setupMock(repo)

			svc := New(repo, zap.NewNop())

			client, err := svc.VerifySecret(ctx, tt.clientID, tt.rawSecret)

			if tt.wantErr != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErr, domainerrors.ErrInvalidCredentials) ||
					errors.Is(tt.wantErr, domainerrors.ErrOAuthClientNotFound) {
					require.ErrorIs(t, err, tt.wantErr)
				} else {
					assert.Contains(t, err.Error(), tt.wantErr.Error())
				}
				assert.Nil(t, client)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)

			if tt.check != nil {
				tt.check(t, client)
			}
		})
	}
}
