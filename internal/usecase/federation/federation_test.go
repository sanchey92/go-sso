package federation

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
	"github.com/sanchey92/sso/internal/usecase/federation/mocks"
)

func TestService_InitiateOAuth(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		setup    func(ss *mocks.StateStore, ip *mocks.IdentityProvider)
		wantErr  error
	}{
		{
			name:     "success",
			provider: "google",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider) {
				ss.EXPECT().
					Set(mock.Anything, mock.MatchedBy(func(key string) bool {
						return len(key) > len(stateKeyPrefix)
					}), mock.Anything, 10*time.Minute).
					Return(nil)

				ip.EXPECT().
					GetAuthURL(mock.Anything, mock.Anything).
					Return("https://accounts.google.com/o/oauth2/v2/auth?state=abc")
			},
		},
		{
			name:     "unknown_provider",
			provider: "facebook",
			setup:    func(ss *mocks.StateStore, ip *mocks.IdentityProvider) {},
			wantErr:  domainerrors.ErrProviderNotSupported,
		},
		{
			name:     "state_store_error",
			provider: "google",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider) {
				ss.EXPECT().
					Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(fmt.Errorf("redis connection refused"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateStore := mocks.NewStateStore(t)
			identityProvider := mocks.NewIdentityProvider(t)
			tt.setup(stateStore, identityProvider)

			providers := map[string]IdentityProvider{
				"google": identityProvider,
			}

			svc := New(providers, nil, nil, stateStore, 10*time.Minute, zap.NewNop())

			url, err := svc.InitiateOAuth(t.Context(), tt.provider)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, url)
				return
			}

			if tt.name == "state_store_error" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "save state")
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, url)
		})
	}
}

func TestService_HandleCallback(t *testing.T) {
	validState := `{"provider":"google","verifier":"test-verifier"}`

	tests := []struct {
		name     string
		provider string
		code     string
		state    string
		setup    func(
			ss *mocks.StateStore,
			ip *mocks.IdentityProvider,
			ul *mocks.UserLinker,
			ti *mocks.TokenIssuer,
		)
		wantErr error
	}{
		{
			name:     "existing_federated_identity",
			provider: "google",
			code:     "auth-code",
			state:    "valid-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"valid-state").Return(validState, nil)
				ss.EXPECT().Delete(mock.Anything, stateKeyPrefix+"valid-state").Return(nil)

				ip.EXPECT().ExchangeCode(mock.Anything, "auth-code", "test-verifier").
					Return(&model.ProviderUser{
						ProviderUserID: "google-123",
						Email:          "user@example.com",
						EmailVerified:  true,
						Name:           "Test User",
					}, nil)

				ul.EXPECT().LinkIdentityTx(mock.Anything, "google", mock.MatchedBy(func(pu *model.ProviderUser) bool {
					return pu.ProviderUserID == "google-123" && pu.Email == "user@example.com"
				})).Return(&model.User{ID: "user-uuid-1", Email: "user@example.com"}, false, nil)

				ti.EXPECT().IssueTokenPair(mock.Anything, "user-uuid-1", "", []string(nil)).
					Return(&model.TokenPair{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 900}, nil)
			},
		},
		{
			name:     "auto_provision_new_user",
			provider: "google",
			code:     "auth-code",
			state:    "valid-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"valid-state").Return(validState, nil)
				ss.EXPECT().Delete(mock.Anything, stateKeyPrefix+"valid-state").Return(nil)

				ip.EXPECT().ExchangeCode(mock.Anything, "auth-code", "test-verifier").
					Return(&model.ProviderUser{
						ProviderUserID: "google-new",
						Email:          "new@example.com",
						EmailVerified:  true,
						Name:           "New User",
					}, nil)

				ul.EXPECT().LinkIdentityTx(mock.Anything, "google", mock.MatchedBy(func(pu *model.ProviderUser) bool {
					return pu.ProviderUserID == "google-new" && pu.Email == "new@example.com"
				})).Return(&model.User{ID: "new-user-uuid", Email: "new@example.com"}, true, nil)

				ti.EXPECT().IssueTokenPair(mock.Anything, "new-user-uuid", "", []string(nil)).
					Return(&model.TokenPair{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 900}, nil)
			},
		},
		{
			name:     "account_linking_existing_email",
			provider: "google",
			code:     "auth-code",
			state:    "valid-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"valid-state").Return(validState, nil)
				ss.EXPECT().Delete(mock.Anything, stateKeyPrefix+"valid-state").Return(nil)

				ip.EXPECT().ExchangeCode(mock.Anything, "auth-code", "test-verifier").
					Return(&model.ProviderUser{
						ProviderUserID: "google-link",
						Email:          "existing@example.com",
						EmailVerified:  true,
					}, nil)

				ul.EXPECT().LinkIdentityTx(mock.Anything, "google", mock.Anything).
					Return(&model.User{ID: "existing-id"}, false, nil)

				ti.EXPECT().IssueTokenPair(mock.Anything, "existing-id", "", []string(nil)).
					Return(&model.TokenPair{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 900}, nil)
			},
		},
		{
			name:     "invalid_state",
			provider: "google",
			code:     "auth-code",
			state:    "bad-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"bad-state").
					Return("", domainerrors.ErrKeyNotFound)
			},
			wantErr: domainerrors.ErrInvalidOAuthState,
		},
		{
			name:     "provider_mismatch_in_state",
			provider: "github",
			code:     "auth-code",
			state:    "valid-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"valid-state").Return(validState, nil)
				ss.EXPECT().Delete(mock.Anything, stateKeyPrefix+"valid-state").Return(nil)
			},
			wantErr: domainerrors.ErrInvalidOAuthState,
		},
		{
			name:     "email_not_verified",
			provider: "google",
			code:     "auth-code",
			state:    "valid-state",
			setup: func(ss *mocks.StateStore, ip *mocks.IdentityProvider, ul *mocks.UserLinker, ti *mocks.TokenIssuer) {
				ss.EXPECT().Get(mock.Anything, stateKeyPrefix+"valid-state").Return(validState, nil)
				ss.EXPECT().Delete(mock.Anything, stateKeyPrefix+"valid-state").Return(nil)

				ip.EXPECT().ExchangeCode(mock.Anything, "auth-code", "test-verifier").
					Return(&model.ProviderUser{
						ProviderUserID: "google-456",
						Email:          "unverified@example.com",
						EmailVerified:  false,
					}, nil)
			},
			wantErr: domainerrors.ErrProviderEmailNotVerified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateStore := mocks.NewStateStore(t)
			identityProvider := mocks.NewIdentityProvider(t)
			userLinker := mocks.NewUserLinker(t)
			tokenIssuer := mocks.NewTokenIssuer(t)

			tt.setup(stateStore, identityProvider, userLinker, tokenIssuer)

			providers := map[string]IdentityProvider{
				"google": identityProvider,
			}

			svc := New(providers, userLinker, tokenIssuer, stateStore, 10*time.Minute, zap.NewNop())

			pair, err := svc.HandleCallback(t.Context(), tt.provider, tt.code, tt.state)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, pair)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pair)
			assert.NotEmpty(t, pair.AccessToken)
			assert.NotEmpty(t, pair.RefreshToken)
		})
	}
}
