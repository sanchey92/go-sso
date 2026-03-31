package handler

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/internal/adapter/driving/grpc/handler/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func newTestHandler(t *testing.T) (
	*Handler,
	*mocks.TokenIntrospector,
	*mocks.UserGetter,
	*mocks.IntrospectionCache,
) {
	t.Helper()
	ti := mocks.NewTokenIntrospector(t)
	ug := mocks.NewUserGetter(t)
	ic := mocks.NewIntrospectionCache(t)
	h := New(ti, ug, ic, 5*time.Minute, zap.NewNop())
	return h, ti, ug, ic
}

func TestIntrospectToken(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name        string
		token       string
		setup       func(*mocks.TokenIntrospector, *mocks.IntrospectionCache)
		wantActive  bool
		wantSubject string
	}{
		{
			name:  "valid token, cache miss",
			token: "valid-jwt",
			setup: func(ti *mocks.TokenIntrospector, ic *mocks.IntrospectionCache) {
				// Cache miss
				ic.EXPECT().Get(mock.Anything, mock.Anything).
					Return("", domainerrors.ErrKeyNotFound)
				// Token valid
				ti.EXPECT().ValidateToken("valid-jwt").
					Return(&model.TokenClaims{
						Subject:   "user-123",
						Issuer:    "http://localhost:8080",
						Audience:  "sso",
						ExpiresAt: now.Add(15 * time.Minute),
						IssuedAt:  now,
					}, nil)
				// Cache set
				ic.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 5*time.Minute).
					Return(nil)
			},
			wantActive:  true,
			wantSubject: "user-123",
		},
		{
			name:  "expired token, cache miss",
			token: "expired-jwt",
			setup: func(ti *mocks.TokenIntrospector, ic *mocks.IntrospectionCache) {
				ic.EXPECT().Get(mock.Anything, mock.Anything).
					Return("", domainerrors.ErrKeyNotFound)
				ti.EXPECT().ValidateToken("expired-jwt").
					Return(nil, domainerrors.ErrTokenExpired)
				ic.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, 5*time.Minute).
					Return(nil)
			},
			wantActive: false,
		},
		{
			name:  "cache hit",
			token: "cached-jwt",
			setup: func(_ *mocks.TokenIntrospector, ic *mocks.IntrospectionCache) {
				cached := cachedIntrospection{
					Active:  true,
					Subject: "user-456",
					Issuer:  "http://localhost:8080",
				}
				data, _ := json.Marshal(cached)
				ic.EXPECT().Get(mock.Anything, mock.Anything).
					Return(string(data), nil)
			},
			wantActive:  true,
			wantSubject: "user-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ti, _, ic := newTestHandler(t)
			tt.setup(ti, ic)

			resp, err := h.IntrospectToken(t.Context(), &ssov1.IntrospectTokenRequest{
				Token: tt.token,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.wantActive, resp.GetActive())
			if tt.wantSubject != "" {
				assert.Equal(t, tt.wantSubject, resp.GetSubject())
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		setup     func(*mocks.TokenIntrospector, *mocks.UserGetter)
		wantCode  codes.Code
		wantValid bool
	}{
		{
			name:  "valid token and user",
			token: "good-jwt",
			setup: func(ti *mocks.TokenIntrospector, ug *mocks.UserGetter) {
				ti.EXPECT().ValidateToken("good-jwt").
					Return(&model.TokenClaims{Subject: "user-1"}, nil)
				ug.EXPECT().GetByID(mock.Anything, "user-1").
					Return(&model.User{
						ID:            "user-1",
						Email:         "test@example.com",
						EmailVerified: true,
					}, nil)
			},
			wantValid: true,
		},
		{
			name:  "invalid token",
			token: "bad-jwt",
			setup: func(ti *mocks.TokenIntrospector, _ *mocks.UserGetter) {
				ti.EXPECT().ValidateToken("bad-jwt").
					Return(nil, domainerrors.ErrInvalidToken)
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name:  "user not found",
			token: "orphan-jwt",
			setup: func(ti *mocks.TokenIntrospector, ug *mocks.UserGetter) {
				ti.EXPECT().ValidateToken("orphan-jwt").
					Return(&model.TokenClaims{Subject: "deleted-user"}, nil)
				ug.EXPECT().GetByID(mock.Anything, "deleted-user").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ti, ug, _ := newTestHandler(t)
			tt.setup(ti, ug)

			resp, err := h.ValidateToken(t.Context(), &ssov1.ValidateTokenRequest{
				Token: tt.token,
			})

			if tt.wantCode != codes.OK {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, resp.GetValid())
		})
	}
}

func TestGetUser(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name      string
		userID    string
		setup     func(*mocks.UserGetter)
		wantCode  codes.Code
		wantEmail string
	}{
		{
			name:   "existing user",
			userID: "user-1",
			setup: func(ug *mocks.UserGetter) {
				ug.EXPECT().GetByID(mock.Anything, "user-1").
					Return(&model.User{
						ID:            "user-1",
						Email:         "alice@example.com",
						EmailVerified: true,
						MFAEnabled:    false,
						Status:        model.UserStatusActive,
						CreatedAt:     now,
					}, nil)
			},
			wantEmail: "alice@example.com",
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			setup: func(ug *mocks.UserGetter) {
				ug.EXPECT().GetByID(mock.Anything, "nonexistent").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantCode: codes.NotFound,
		},
		{
			name:     "empty user_id",
			userID:   "",
			setup:    func(_ *mocks.UserGetter) {},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, ug, _ := newTestHandler(t)
			tt.setup(ug)

			resp, err := h.GetUser(t.Context(), &ssov1.GetUserRequest{
				UserId: tt.userID,
			})

			if tt.wantCode != codes.OK {
				require.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantEmail, resp.GetEmail())
		})
	}
}

func TestBatchValidateTokens(t *testing.T) {
	tests := []struct {
		name      string
		tokens    []string
		setup     func(*mocks.TokenIntrospector)
		wantValid int
		wantTotal int
	}{
		{
			name:   "mixed valid and invalid",
			tokens: []string{"good-1", "bad", "good-2"},
			setup: func(ti *mocks.TokenIntrospector) {
				ti.EXPECT().ValidateToken("good-1").
					Return(&model.TokenClaims{Subject: "u1"}, nil)
				ti.EXPECT().ValidateToken("bad").
					Return(nil, domainerrors.ErrInvalidToken)
				ti.EXPECT().ValidateToken("good-2").
					Return(&model.TokenClaims{Subject: "u2"}, nil)
			},
			wantValid: 2,
			wantTotal: 3,
		},
		{
			name:      "empty request",
			tokens:    nil,
			setup:     func(_ *mocks.TokenIntrospector) {},
			wantValid: 0,
			wantTotal: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ti, _, _ := newTestHandler(t)
			tt.setup(ti)

			resp, err := h.BatchValidateTokens(t.Context(), &ssov1.BatchValidateTokensRequest{
				Tokens: tt.tokens,
			})

			require.NoError(t, err)
			assert.Len(t, resp.GetResults(), tt.wantTotal)

			valid := 0
			for _, r := range resp.GetResults() {
				if r.GetValid() {
					valid++
				}
			}
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}
