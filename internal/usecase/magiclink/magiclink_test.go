package magiclink

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/magiclink/mocks"
)

func TestService_RequestMagicLink(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		email     string
		setupMock func(*mocks.UserGetter, *mocks.CacheStore, *mocks.LinkSender)
		wantErr   string
	}{
		{
			name:  "success",
			email: "user@example.com",
			setupMock: func(ug *mocks.UserGetter, cs *mocks.CacheStore, ms *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-1", EmailVerified: true}, nil)
				cs.EXPECT().Set(mock.Anything, mock.MatchedBy(func(key string) bool {
					return strings.HasPrefix(key, "magic:")
				}), "user-1", 15*time.Minute).Return(nil)
				ms.EXPECT().SendMagicLinkEmail(mock.Anything, "user@example.com", mock.Anything).
					Return(nil)
			},
		},
		{
			name:  "unknown email — returns nil (anti-enumeration)",
			email: "nobody@example.com",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.CacheStore, _ *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "nobody@example.com").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			// wantErr пустой → проверяем что err == nil
		},
		{
			name:  "unverified email — returns nil",
			email: "unverified@example.com",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.CacheStore, _ *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "unverified@example.com").
					Return(&model.User{ID: "user-2", EmailVerified: false}, nil)
			},
		},
		{
			name:  "cache error — returns nil (swallowed)",
			email: "user@example.com",
			setupMock: func(ug *mocks.UserGetter, cs *mocks.CacheStore, _ *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-1", EmailVerified: true}, nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("redis down"))
			},
		},
		{
			name:  "email error — returns nil (swallowed)",
			email: "user@example.com",
			setupMock: func(ug *mocks.UserGetter, cs *mocks.CacheStore, ms *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-1", EmailVerified: true}, nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				ms.EXPECT().SendMagicLinkEmail(mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("smtp error"))
			},
		},
		{
			name:  "db error — returns wrapped error",
			email: "user@example.com",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.CacheStore, _ *mocks.LinkSender) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(nil, errors.New("db down"))
			},
			wantErr: "get user by email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ug := mocks.NewUserGetter(t)
			cs := mocks.NewCacheStore(t)
			ms := mocks.NewLinkSender(t)
			ti := mocks.NewTokenIssuer(t) // не используется в Request, но нужен конструктору
			tt.setupMock(ug, cs, ms)

			svc := New(ug, cs, ms, ti, 15*time.Minute, zap.NewNop())
			err := svc.RequestMagicLink(ctx, tt.email)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestService_VerifyMagicLink(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		token     string
		setupMock func(*mocks.CacheStore, *mocks.TokenIssuer)
		want      *model.TokenPair
		wantErr   error // ErrorIs (точное сравнение)
	}{
		{
			name:  "success",
			token: "valid-token",
			setupMock: func(cs *mocks.CacheStore, ti *mocks.TokenIssuer) {
				// Ключ = "magic:" + SHA-256("valid-token")
				cs.EXPECT().Get(mock.Anything, mock.MatchedBy(func(key string) bool {
					return strings.HasPrefix(key, "magic:")
				})).Return("user-1", nil)
				cs.EXPECT().Delete(mock.Anything, mock.Anything).Return(nil)
				ti.EXPECT().IssueTokenPair(mock.Anything, "user-1", "", []string(nil)).
					Return(&model.TokenPair{
						AccessToken:  "at",
						RefreshToken: "rt",
						ExpiresIn:    900,
					}, nil)
			},
			want: &model.TokenPair{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 900},
		},
		{
			name:  "token not found",
			token: "unknown-token",
			setupMock: func(cs *mocks.CacheStore, _ *mocks.TokenIssuer) {
				cs.EXPECT().Get(mock.Anything, mock.Anything).
					Return("", domainerrors.ErrKeyNotFound)
			},
			wantErr: domainerrors.ErrMagicLinkNotFound,
		},
		{
			name:  "delete fails — still returns tokens",
			token: "valid-token",
			setupMock: func(cs *mocks.CacheStore, ti *mocks.TokenIssuer) {
				cs.EXPECT().Get(mock.Anything, mock.Anything).Return("user-1", nil)
				cs.EXPECT().Delete(mock.Anything, mock.Anything).
					Return(errors.New("redis del"))
				ti.EXPECT().IssueTokenPair(mock.Anything, "user-1", "", []string(nil)).
					Return(&model.TokenPair{
						AccessToken:  "at",
						RefreshToken: "rt",
						ExpiresIn:    900,
					}, nil)
			},
			want: &model.TokenPair{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 900},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ug := mocks.NewUserGetter(t)
			cs := mocks.NewCacheStore(t)
			ms := mocks.NewLinkSender(t)
			ti := mocks.NewTokenIssuer(t)
			tt.setupMock(cs, ti)

			svc := New(ug, cs, ms, ti, 15*time.Minute, zap.NewNop())
			pair, err := svc.VerifyMagicLink(ctx, tt.token)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, pair)
		})
	}
}
