package token

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/token/mocks"
	"github.com/sanchey92/sso/pkg/crypto"
)

func TestService_IssueTokenPair(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		userID    string
		clientID  string
		scopes    []string
		setupMock func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository)
		wantErr   string
		check     func(t *testing.T, pair *model.TokenPair)
	}{
		{
			name:   "successful issue",
			userID: "user-1",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				tg.EXPECT().GenerateToken("user-1", "sso").
					Return("access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("raw-refresh", "hash-refresh", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.MatchedBy(func(rt *model.RefreshToken) bool {
					return rt.UserID == "user-1" &&
						rt.TokenHash == "hash-refresh" &&
						rt.FamilyID != "" &&
						!rt.Revoked
				})).Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "access-jwt", pair.AccessToken)
				assert.Equal(t, "raw-refresh", pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn)
			},
		},
		{
			name:   "generate access token fails",
			userID: "user-1",
			setupMock: func(tg *mocks.TokenGenerator, _ *mocks.RefreshTokenRepository) {
				tg.EXPECT().GenerateToken("user-1", "sso").
					Return("", errors.New("sign failed"))
			},
			wantErr: "generate access token: sign failed",
		},
		{
			name:   "generate refresh token fails",
			userID: "user-1",
			setupMock: func(tg *mocks.TokenGenerator, _ *mocks.RefreshTokenRepository) {
				tg.EXPECT().GenerateToken("user-1", "sso").
					Return("access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("", "", errors.New("rand failed"))
			},
			wantErr: "generate refresh token: rand failed",
		},
		{
			name:   "save refresh token fails",
			userID: "user-1",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				tg.EXPECT().GenerateToken("user-1", "sso").
					Return("access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("raw", "hash", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(errors.New("db error"))
			},
			wantErr: "save refresh token: db error",
		},
		{
			name:     "with client_id and scopes",
			userID:   "user-1",
			clientID: "client-abc",
			scopes:   []string{"openid", "profile"},
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				tg.EXPECT().GenerateToken("user-1", "sso").
					Return("access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("raw", "hash", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.MatchedBy(func(rt *model.RefreshToken) bool {
					return rt.ClientID == "client-abc" &&
						len(rt.Scopes) == 2 &&
						rt.Scopes[0] == "openid" &&
						rt.Scopes[1] == "profile"
				})).Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "access-jwt", pair.AccessToken)
				assert.Equal(t, "raw", pair.RefreshToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenGen := mocks.NewTokenGenerator(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			tt.setupMock(tokenGen, refreshRepo)

			svc := New(tokenGen, refreshRepo, time.Minute, time.Hour, zap.NewNop())

			pair, err := svc.IssueTokenPair(ctx, tt.userID, tt.clientID, tt.scopes)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, pair)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pair)

			if tt.check != nil {
				tt.check(t, pair)
			}
		})
	}
}

func TestService_RefreshTokens(t *testing.T) {
	ctx := t.Context()

	validRT := &model.RefreshToken{
		ID:        "rt-uuid",
		TokenHash: crypto.HashToken("valid-refresh-token"),
		UserID:    "user-uuid",
		FamilyID:  "family-uuid",
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	tests := []struct {
		name         string
		refreshToken string
		setupMock    func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository)
		wantErr      string
		check        func(t *testing.T, pair *model.TokenPair)
	}{
		{
			name:         "successful refresh",
			refreshToken: "valid-refresh-token",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				tg.EXPECT().GenerateToken("user-uuid", "sso").
					Return("new-access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("new-raw-token", "new-hash", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.MatchedBy(func(rt *model.RefreshToken) bool {
					return rt.FamilyID == "family-uuid" &&
						rt.UserID == "user-uuid" &&
						rt.TokenHash == "new-hash" &&
						!rt.Revoked
				})).Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "new-access-jwt", pair.AccessToken)
				assert.Equal(t, "new-raw-token", pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn)
			},
		},
		{
			name:         "token not found",
			refreshToken: "unknown-token",
			setupMock: func(_ *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("unknown-token")).
					Return(nil, domainerrors.ErrInvalidToken)
			},
			wantErr: domainerrors.ErrInvalidToken.Error(),
		},
		{
			name:         "expired token",
			refreshToken: "valid-refresh-token",
			setupMock: func(_ *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				expired := *validRT
				expired.ExpiresAt = time.Now().Add(-time.Hour)
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(&expired, nil)
			},
			wantErr: domainerrors.ErrTokenExpired.Error(),
		},
		{
			name:         "revoked token triggers family revocation",
			refreshToken: "valid-refresh-token",
			setupMock: func(_ *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				revoked := *validRT
				revoked.Revoked = true
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(&revoked, nil)
				rr.EXPECT().RevokeByFamilyID(mock.Anything, "family-uuid").
					Return(nil)
			},
			wantErr: domainerrors.ErrTokenRevoked.Error(),
		},
		{
			name:         "revoke current token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(_ *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(errors.New("db error"))
			},
			wantErr: "revoke current token: db error",
		},
		{
			name:         "generate access token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				tg.EXPECT().GenerateToken("user-uuid", "sso").
					Return("", errors.New("sign failed"))
			},
			wantErr: "generate access token: sign failed",
		},
		{
			name:         "generate refresh token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				tg.EXPECT().GenerateToken("user-uuid", "sso").
					Return("new-access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("", "", errors.New("rand failed"))
			},
			wantErr: "generate refresh token: rand failed",
		},
		{
			name:         "save new refresh token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(tg *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				tg.EXPECT().GenerateToken("user-uuid", "sso").
					Return("new-access-jwt", nil)
				tg.EXPECT().GenerateRefreshToken().
					Return("new-raw", "new-hash", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(errors.New("insert failed"))
			},
			wantErr: "save refresh token: insert failed",
		},
		{
			name:         "family revocation fails on replay",
			refreshToken: "valid-refresh-token",
			setupMock: func(_ *mocks.TokenGenerator, rr *mocks.RefreshTokenRepository) {
				revoked := *validRT
				revoked.Revoked = true
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("valid-refresh-token")).
					Return(&revoked, nil)
				rr.EXPECT().RevokeByFamilyID(mock.Anything, "family-uuid").
					Return(errors.New("db error"))
			},
			wantErr: "revoke token family: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenGen := mocks.NewTokenGenerator(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			tt.setupMock(tokenGen, refreshRepo)

			svc := New(tokenGen, refreshRepo, time.Minute, time.Hour, zap.NewNop())

			pair, err := svc.RefreshTokens(ctx, tt.refreshToken)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, pair)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pair)

			if tt.check != nil {
				tt.check(t, pair)
			}
		})
	}
}

func TestService_RevokeToken(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		rawToken  string
		setupMock func(rr *mocks.RefreshTokenRepository)
		wantErr   string
	}{
		{
			name:     "success",
			rawToken: "token-to-revoke",
			setupMock: func(rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("token-to-revoke")).
					Return(&model.RefreshToken{ID: "rt-1", Revoked: false, UserID: "u1"}, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-1").Return(nil)
			},
		},
		{
			name:     "already revoked — no error",
			rawToken: "revoked-token",
			setupMock: func(rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("revoked-token")).
					Return(&model.RefreshToken{ID: "rt-2", Revoked: true}, nil)
			},
		},
		{
			name:     "token not found",
			rawToken: "unknown",
			setupMock: func(rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, crypto.HashToken("unknown")).
					Return(nil, domainerrors.ErrInvalidToken)
			},
			wantErr: domainerrors.ErrInvalidToken.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenGen := mocks.NewTokenGenerator(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			tt.setupMock(refreshRepo)

			svc := New(tokenGen, refreshRepo, time.Minute, time.Hour, zap.NewNop())

			err := svc.RevokeToken(ctx, tt.rawToken)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
