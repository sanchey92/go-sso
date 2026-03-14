package oauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/oauth/mocks"
)

const testAuthCodeTTL = 60 * time.Second

func TestService_Authorize(t *testing.T) {
	ctx := t.Context()

	validParams := &model.AuthorizationCode{
		ClientID:            "client-123",
		UserID:              "user-456",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	validClient := &model.OAuthClient{
		ID:           "client-123",
		Name:         "Test App",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	tests := []struct {
		name       string
		params     *model.AuthorizationCode
		setupMocks func(cg *mocks.ClientGetter, cs *mocks.AuthCodeStore)
		wantCode   bool
		wantErr    error
		wantErrMsg string
	}{
		{
			name:   "successful authorization",
			params: validParams,
			setupMocks: func(cg *mocks.ClientGetter, cs *mocks.AuthCodeStore) {
				cg.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(validClient, nil)
				cs.EXPECT().
					Set(mock.Anything, mock.MatchedBy(func(key string) bool {
						return len(key) > len("auth_code:")
					}), mock.AnythingOfType("string"), testAuthCodeTTL).
					Return(nil)
			},
			wantCode: true,
		},
		{
			name:   "client not found",
			params: validParams,
			setupMocks: func(cg *mocks.ClientGetter, cs *mocks.AuthCodeStore) {
				cg.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(nil, domainerrors.ErrOAuthClientNotFound)
			},
			wantErr: domainerrors.ErrOAuthClientNotFound,
		},
		{
			name: "invalid redirect_uri",
			params: &model.AuthorizationCode{
				ClientID:            "client-123",
				UserID:              "user-456",
				RedirectURI:         "https://evil.com/callback",
				Scope:               "openid",
				CodeChallenge:       "challenge",
				CodeChallengeMethod: "S256",
			},
			setupMocks: func(cg *mocks.ClientGetter, cs *mocks.AuthCodeStore) {
				cg.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(validClient, nil)
			},
			wantErr: domainerrors.ErrInvalidRedirectURI,
		},
		{
			name:   "redis save error",
			params: validParams,
			setupMocks: func(cg *mocks.ClientGetter, cs *mocks.AuthCodeStore) {
				cg.EXPECT().
					GetClientByID(mock.Anything, "client-123").
					Return(validClient, nil)
				cs.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(fmt.Errorf("connection refused"))
			},
			wantErrMsg: "save auth code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientGetter := mocks.NewClientGetter(t)
			codeStore := mocks.NewAuthCodeStore(t)
			tt.setupMocks(clientGetter, codeStore)

			svc := New(
				clientGetter,
				mocks.NewClientAuthenticator(t),
				codeStore,
				mocks.NewTokenIssuer(t),
				testAuthCodeTTL,
				zap.NewNop(),
			)

			code, err := svc.Authorize(ctx, tt.params)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, code)
				return
			}
			if tt.wantErrMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
				assert.Empty(t, code)
				return
			}

			require.NoError(t, err)
			if tt.wantCode {
				assert.NotEmpty(t, code)
			}
		})
	}
}
