package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/user/mocks"
)

func TestService_Register(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender)
		wantErr   string
		check     func(t *testing.T, user *model.User)
	}{
		{
			name:     "successful registration",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) {
						u.ID = "generated-uuid"
					}).
					Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "generated-uuid", mock.Anything).Return(nil)
				es.EXPECT().SendVerificationEmail(mock.Anything, "user@example.com", mock.Anything).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "generated-uuid", user.ID)
				assert.Equal(t, "user@example.com", user.Email)
				assert.Equal(t, "hashed_password", user.PasswordHash)
				assert.Equal(t, model.UserStatusActive, user.Status)
				assert.False(t, user.EmailVerified)
				assert.False(t, user.MFAEnabled)
			},
		},
		{
			name:     "email normalized to lowercase and trimmed",
			email:    "  User@Example.COM  ",
			password: "securepassword",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u *model.User) bool {
					return u.Email == "user@example.com"
				})).Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				es.EXPECT().SendVerificationEmail(mock.Anything, "user@example.com", mock.Anything).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "empty email",
			email:     "",
			password:  "securepassword",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {},
			wantErr:   "email: cannot be empty",
		},
		{
			name:      "invalid email format",
			email:     "not-an-email",
			password:  "securepassword",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {},
			wantErr:   "email: invalid format",
		},
		{
			name:      "password too short",
			email:     "user@example.com",
			password:  "short",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:      "empty password",
			email:     "user@example.com",
			password:  "",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:     "hasher returns error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("", errors.New("hash failed"))
			},
			wantErr: "hash password: hash failed",
		},
		{
			name:     "email already exists",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Return(domainerrors.ErrEmailAlreadyExists)
			},
			wantErr: domainerrors.ErrEmailAlreadyExists.Error(),
		},
		{
			name:     "repository returns unexpected error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Return(errors.New("db connection lost"))
			},
			wantErr: "create user: db connection lost",
		},
		{
			name:     "password exactly 8 characters is valid",
			email:    "user@example.com",
			password: "12345678",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("12345678").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				es.EXPECT().SendVerificationEmail(mock.Anything, "user@example.com", mock.Anything).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "password 7 characters is invalid",
			email:     "user@example.com",
			password:  "1234567",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewPasswordHasher(t)
			userRepo := mocks.NewUserRepository(t)
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(hasher, userRepo, cache, emailSender)

			svc := New(userRepo, hasher, cache, emailSender, mocks.NewTokenRevoker(t), zap.NewNop())

			user, err := svc.Register(ctx, tt.email, tt.password)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, user)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, user)

			if tt.check != nil {
				tt.check(t, user)
			}
		})
	}
}

func TestService_VerifyEmail(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		token     string
		setupMock func(cs *mocks.CacheStore, ur *mocks.UserRepository)
		wantErr   error
	}{
		{
			name:  "success",
			token: "valid-token",
			setupMock: func(cs *mocks.CacheStore, ur *mocks.UserRepository) {
				cs.EXPECT().Get(mock.Anything, "verify:valid-token").Return("user-123", nil)
				ur.EXPECT().UpdateEmailVerified(mock.Anything, "user-123", true).Return(nil)
				cs.EXPECT().Delete(mock.Anything, "verify:valid-token").Return(nil)
			},
			wantErr: nil,
		},
		{
			name:  "invalid token (key not found)",
			token: "bad-token",
			setupMock: func(cs *mocks.CacheStore, _ *mocks.UserRepository) {
				cs.EXPECT().Get(mock.Anything, "verify:bad-token").
					Return("", domainerrors.ErrKeyNotFound)
			},
			wantErr: domainerrors.ErrInvalidVerificationToken,
		},
		{
			name:  "cache get unexpected error",
			token: "some-token",
			setupMock: func(cs *mocks.CacheStore, _ *mocks.UserRepository) {
				cs.EXPECT().Get(mock.Anything, "verify:some-token").
					Return("", errors.New("redis connection lost"))
			},
		},
		{
			name:  "user not found",
			token: "orphan-token",
			setupMock: func(cs *mocks.CacheStore, ur *mocks.UserRepository) {
				cs.EXPECT().Get(mock.Anything, "verify:orphan-token").Return("missing-user", nil)
				ur.EXPECT().UpdateEmailVerified(mock.Anything, "missing-user", true).
					Return(domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrUserNotFound,
		},
		{
			name:  "delete fails — still success",
			token: "valid-token",
			setupMock: func(cs *mocks.CacheStore, ur *mocks.UserRepository) {
				cs.EXPECT().Get(mock.Anything, "verify:valid-token").Return("user-456", nil)
				ur.EXPECT().UpdateEmailVerified(mock.Anything, "user-456", true).Return(nil)
				cs.EXPECT().Delete(mock.Anything, "verify:valid-token").
					Return(errors.New("redis del failed"))
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := mocks.NewCacheStore(t)
			userRepo := mocks.NewUserRepository(t)
			tt.setupMock(cache, userRepo)

			svc := New(userRepo, mocks.NewPasswordHasher(t), cache, mocks.NewEmailSender(t), mocks.NewTokenRevoker(t), zap.NewNop())

			err := svc.VerifyEmail(ctx, tt.token)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			if tt.name == "cache get unexpected error" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "get verification token")
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestService_Register_VerificationEmailFlow(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		setupMock func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender)
	}{
		{
			name: "cache set fails — user still returned",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, _ *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) { u.ID = "user-1" }).
					Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-1", mock.Anything).
					Return(errors.New("redis down"))
			},
		},
		{
			name: "email send fails — user still returned",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) { u.ID = "user-2" }).
					Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-2", mock.Anything).Return(nil)
				es.EXPECT().SendVerificationEmail(mock.Anything, "test@example.com", mock.Anything).
					Return(errors.New("smtp error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewPasswordHasher(t)
			userRepo := mocks.NewUserRepository(t)
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(hasher, userRepo, cache, emailSender)

			svc := New(userRepo, hasher, cache, emailSender, mocks.NewTokenRevoker(t), zap.NewNop())

			user, err := svc.Register(ctx, "test@example.com", "securepassword")

			require.NoError(t, err)
			require.NotNil(t, user)
		})
	}
}

func TestService_RequestPasswordReset(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		email     string
		setupMock func(ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender)
		wantErr   bool
	}{
		{
			name:  "successful reset request",
			email: "user@example.com",
			setupMock: func(ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-123", Email: "user@example.com"}, nil)
				cs.EXPECT().Set(mock.Anything, mock.MatchedBy(func(key string) bool {
					return strings.HasPrefix(key, "reset:")
				}), "user-123", 1*time.Hour).Return(nil)
				es.EXPECT().SendPasswordResetEmail(mock.Anything, "user@example.com", mock.Anything).
					Return(nil)
			},
		},
		{
			name:  "non-existent email returns nil (anti-enumeration)",
			email: "nobody@example.com",
			setupMock: func(ur *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {
				ur.EXPECT().GetByEmail(mock.Anything, "nobody@example.com").
					Return(nil, domainerrors.ErrUserNotFound)
			},
		},
		{
			name:  "email send failure does not return error",
			email: "user@example.com",
			setupMock: func(ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-123", Email: "user@example.com"}, nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-123", 1*time.Hour).Return(nil)
				es.EXPECT().SendPasswordResetEmail(mock.Anything, mock.Anything, mock.Anything).
					Return(fmt.Errorf("smtp error"))
			},
		},
		{
			name:  "cache error returns error",
			email: "user@example.com",
			setupMock: func(ur *mocks.UserRepository, cs *mocks.CacheStore, _ *mocks.EmailSender) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&model.User{ID: "user-123", Email: "user@example.com"}, nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-123", 1*time.Hour).
					Return(fmt.Errorf("redis error"))
			},
			wantErr: true,
		},
		{
			name:  "db error returns error",
			email: "user@example.com",
			setupMock: func(ur *mocks.UserRepository, _ *mocks.CacheStore, _ *mocks.EmailSender) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(nil, fmt.Errorf("db connection: %w", errors.New("timeout")))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ur := mocks.NewUserRepository(t)
			cs := mocks.NewCacheStore(t)
			es := mocks.NewEmailSender(t)
			tt.setupMock(ur, cs, es)

			svc := New(ur, mocks.NewPasswordHasher(t), cs, es, mocks.NewTokenRevoker(t), zap.NewNop())
			err := svc.RequestPasswordReset(ctx, tt.email)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestService_ResetPassword(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		token     string
		password  string
		setupMock func(h *mocks.PasswordHasher, ur *mocks.UserRepository, tr *mocks.TokenRevoker, cs *mocks.CacheStore)
		wantErr   string
	}{
		{
			name:     "successful password reset",
			token:    "valid-token",
			password: "newpassword123",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, tr *mocks.TokenRevoker, cs *mocks.CacheStore) {
				cs.EXPECT().Get(mock.Anything, "reset:valid-token").Return("user-123", nil)
				h.EXPECT().Hash("newpassword123").Return("new-hash", nil)
				ur.EXPECT().UpdatePassword(mock.Anything, "user-123", "new-hash").Return(nil)
				tr.EXPECT().RevokeByUserID(mock.Anything, "user-123").Return(nil)
				cs.EXPECT().Delete(mock.Anything, "reset:valid-token").Return(nil)
			},
		},
		{
			name:     "invalid token",
			token:    "expired-token",
			password: "newpassword123",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.TokenRevoker, cs *mocks.CacheStore) {
				cs.EXPECT().Get(mock.Anything, "reset:expired-token").
					Return("", domainerrors.ErrKeyNotFound)
			},
			wantErr: domainerrors.ErrInvalidResetToken.Error(),
		},
		{
			name:     "password too short",
			token:    "valid-token",
			password: "short",
			setupMock: func(_ *mocks.PasswordHasher, _ *mocks.UserRepository, _ *mocks.TokenRevoker, _ *mocks.CacheStore) {
				// validatePassword fails before any external calls
			},
			wantErr: "password: must be at least 8 characters",
		},
		{
			name:     "revoke failure does not return error",
			token:    "valid-token",
			password: "newpassword123",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, tr *mocks.TokenRevoker, cs *mocks.CacheStore) {
				cs.EXPECT().Get(mock.Anything, "reset:valid-token").Return("user-123", nil)
				h.EXPECT().Hash("newpassword123").Return("new-hash", nil)
				ur.EXPECT().UpdatePassword(mock.Anything, "user-123", "new-hash").Return(nil)
				tr.EXPECT().RevokeByUserID(mock.Anything, "user-123").
					Return(fmt.Errorf("db error"))
				cs.EXPECT().Delete(mock.Anything, "reset:valid-token").Return(nil)
			},
			// wantErr пустой — ошибка revoke не пробрасывается
		},
		{
			name:     "delete token failure does not return error",
			token:    "valid-token",
			password: "newpassword123",
			setupMock: func(h *mocks.PasswordHasher, ur *mocks.UserRepository, tr *mocks.TokenRevoker, cs *mocks.CacheStore) {
				cs.EXPECT().Get(mock.Anything, "reset:valid-token").Return("user-123", nil)
				h.EXPECT().Hash("newpassword123").Return("new-hash", nil)
				ur.EXPECT().UpdatePassword(mock.Anything, "user-123", "new-hash").Return(nil)
				tr.EXPECT().RevokeByUserID(mock.Anything, "user-123").Return(nil)
				cs.EXPECT().Delete(mock.Anything, "reset:valid-token").
					Return(fmt.Errorf("redis error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mocks.NewPasswordHasher(t)
			ur := mocks.NewUserRepository(t)
			tr := mocks.NewTokenRevoker(t)
			cs := mocks.NewCacheStore(t)
			tt.setupMock(h, ur, tr, cs)

			svc := New(ur, h, cs, mocks.NewEmailSender(t), tr, zap.NewNop())
			err := svc.ResetPassword(ctx, tt.token, tt.password)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
