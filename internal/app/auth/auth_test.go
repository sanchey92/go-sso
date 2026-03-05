package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/app/auth/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func TestService_Register(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func(h *mocks.Hasher, ur *mocks.UserRepository)
		wantErr   string
		check     func(t *testing.T, user *model.User)
	}{
		{
			name:     "successful registration",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) {
						u.ID = "generated-uuid"
					}).
					Return(nil)
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u *model.User) bool {
					return u.Email == "user@example.com"
				})).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "empty email",
			email:     "",
			password:  "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "email: cannot be empty",
		},
		{
			name:      "invalid email format",
			email:     "not-an-email",
			password:  "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "email: invalid format",
		},
		{
			name:      "password too short",
			email:     "user@example.com",
			password:  "short",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:      "empty password",
			email:     "user@example.com",
			password:  "",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:     "hasher returns error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("", errors.New("hash failed"))
			},
			wantErr: "hash password: hash failed",
		},
		{
			name:     "email already exists",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("12345678").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "password 7 characters is invalid",
			email:     "user@example.com",
			password:  "1234567",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			tokenSrv := mocks.NewTokenService(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			tt.setupMock(hasher, userRepo)

			svc := New(hasher, tokenSrv, userRepo, refreshRepo, time.Minute, time.Hour, zap.NewNop())

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

func TestService_Login(t *testing.T) {
	ctx := context.Background()

	validUser := &model.User{
		ID:            "user-uuid",
		Email:         "user@example.com",
		PasswordHash:  "argon2id-hash",
		EmailVerified: true,
		Status:        model.UserStatusActive,
	}

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func(
			h *mocks.Hasher,
			ur *mocks.UserRepository,
			ts *mocks.TokenService,
			rr *mocks.RefreshTokenRepository,
		)
		wantErr string
		check   func(t *testing.T, pair *LoginResult)
	}{
		{
			name:     "successful login",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("access-jwt-token", nil)
				rr.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(nil)
			},
			check: func(t *testing.T, pair *LoginResult) {
				assert.Equal(t, "access-jwt-token", pair.AccessToken)
				assert.NotEmpty(t, pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn) // time.Minute = 60s
			},
		},
		{
			name:     "user not found returns invalid credentials",
			email:    "nobody@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "nobody@example.com").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "wrong password returns invalid credentials",
			email:    "user@example.com",
			password: "wrongpassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("wrongpassword", "argon2id-hash").
					Return(false, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "email not verified",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				unverified := *validUser
				unverified.EmailVerified = false
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&unverified, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
			},
			wantErr: domainerrors.ErrEmailNotVerified.Error(),
		},
		{
			name:     "repository unexpected error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(nil, errors.New("db connection lost"))
			},
			wantErr: "get user by email: db connection lost",
		},
		{
			name:     "hasher verify error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(false, errors.New("decode failed"))
			},
			wantErr: "verify password: decode failed",
		},
		{
			name:     "token service error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("", errors.New("signing failed"))
			},
			wantErr: "generate access token: signing failed",
		},
		{
			name:     "refresh repo error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("access-jwt-token", nil)
				rr.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(errors.New("insert failed"))
			},
			wantErr: "save refresh token: insert failed",
		},
		{
			name:     "email normalized before lookup",
			email:    "  User@Example.COM  ",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				ur.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				h.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("access-jwt-token", nil)
				rr.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(nil)
			},
			check: func(t *testing.T, pair *LoginResult) {
				assert.NotEmpty(t, pair.AccessToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			tokenSrv := mocks.NewTokenService(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			tt.setupMock(hasher, userRepo, tokenSrv, refreshRepo)

			svc := New(hasher, tokenSrv, userRepo, refreshRepo, time.Minute, time.Hour, zap.NewNop())

			pair, err := svc.Login(ctx, tt.email, tt.password)

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
