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
