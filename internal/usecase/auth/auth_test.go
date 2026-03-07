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

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/auth/mocks"
)

func TestService_Register(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender)
		wantErr   string
		check     func(t *testing.T, user *model.User)
	}{
		{
			name:     "successful registration",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {},
			wantErr:   "email: cannot be empty",
		},
		{
			name:      "invalid email format",
			email:     "not-an-email",
			password:  "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {},
			wantErr:   "email: invalid format",
		},
		{
			name:      "password too short",
			email:     "user@example.com",
			password:  "short",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:      "empty password",
			email:     "user@example.com",
			password:  "",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:     "hasher returns error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("", errors.New("hash failed"))
			},
			wantErr: "hash password: hash failed",
		},
		{
			name:     "email already exists",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
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
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {},
			wantErr:   "password: must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			tokenSrv := mocks.NewTokenService(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(hasher, userRepo, cache, emailSender)

			svc := New(hasher, tokenSrv, userRepo, refreshRepo, cache, emailSender, time.Minute, time.Hour, zap.NewNop())

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
	ctx := context.Background()

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
			wantErr: nil, // not a specific domain error, just check it's an error
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

			svc := New(
				mocks.NewHasher(t),
				mocks.NewTokenService(t),
				userRepo,
				mocks.NewRefreshTokenRepository(t),
				cache,
				mocks.NewEmailSender(t),
				time.Minute, time.Hour,
				zap.NewNop(),
			)

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
	ctx := context.Background()

	tests := []struct {
		name      string
		setupMock func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender)
		wantUser  bool
		wantErr   bool
	}{
		{
			name: "cache set fails — user still returned",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) { u.ID = "user-1" }).
					Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-1", mock.Anything).
					Return(errors.New("redis down"))
			},
			wantUser: true,
		},
		{
			name: "email send fails — user still returned",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository, cs *mocks.CacheStore, es *mocks.EmailSender) {
				h.EXPECT().Hash("securepassword").Return("hashed", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) { u.ID = "user-2" }).
					Return(nil)
				cs.EXPECT().Set(mock.Anything, mock.Anything, "user-2", mock.Anything).Return(nil)
				es.EXPECT().SendVerificationEmail(mock.Anything, "test@example.com", mock.Anything).
					Return(errors.New("smtp error"))
			},
			wantUser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(hasher, userRepo, cache, emailSender)

			svc := New(
				hasher,
				mocks.NewTokenService(t),
				userRepo,
				mocks.NewRefreshTokenRepository(t),
				cache,
				emailSender,
				time.Minute, time.Hour,
				zap.NewNop(),
			)

			user, err := svc.Register(ctx, "test@example.com", "securepassword")

			require.NoError(t, err)
			require.NotNil(t, user)
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
		check   func(t *testing.T, pair *model.TokenPair)
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
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
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
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
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
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
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
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(hasher, userRepo, tokenSrv, refreshRepo)

			svc := New(hasher, tokenSrv, userRepo, refreshRepo, cache, emailSender, time.Minute, time.Hour, zap.NewNop())

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

func TestService_RefreshTokens(t *testing.T) {
	ctx := context.Background()

	validRT := &model.RefreshToken{
		ID:        "rt-uuid",
		TokenHash: hashToken("valid-refresh-token"),
		UserID:    "user-uuid",
		FamilyID:  "family-uuid",
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	tests := []struct {
		name         string
		refreshToken string
		setupMock    func(
			ts *mocks.TokenService,
			rr *mocks.RefreshTokenRepository,
		)
		wantErr string
		check   func(t *testing.T, pair *model.TokenPair)
	}{
		{
			name:         "successful refresh",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("new-access-jwt", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.MatchedBy(func(rt *model.RefreshToken) bool {
					return rt.FamilyID == "family-uuid" &&
						rt.UserID == "user-uuid" &&
						rt.TokenHash != "" &&
						!rt.Revoked
				})).Return(nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "new-access-jwt", pair.AccessToken)
				assert.NotEmpty(t, pair.RefreshToken)
				assert.NotEqual(t, "valid-refresh-token", pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn)
			},
		},
		{
			name:         "token not found",
			refreshToken: "unknown-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, hashToken("unknown-token")).
					Return(nil, domainerrors.ErrInvalidToken)
			},
			wantErr: domainerrors.ErrInvalidToken.Error(),
		},
		{
			name:         "expired token",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				expired := *validRT
				expired.ExpiresAt = time.Now().Add(-time.Hour)
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(&expired, nil)
			},
			wantErr: domainerrors.ErrTokenExpired.Error(),
		},
		{
			name:         "revoked token triggers family revocation",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				revoked := *validRT
				revoked.Revoked = true
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(&revoked, nil)
				rr.EXPECT().RevokeByFamilyID(mock.Anything, "family-uuid").
					Return(nil)
			},
			wantErr: domainerrors.ErrTokenRevoked.Error(),
		},
		{
			name:         "revoke current token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(errors.New("db error"))
			},
			wantErr: "revoke current token: db error",
		},
		{
			name:         "generate access token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("", errors.New("sign failed"))
			},
			wantErr: "generate access token: sign failed",
		},
		{
			name:         "save new refresh token fails",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(validRT, nil)
				rr.EXPECT().Revoke(mock.Anything, "rt-uuid").
					Return(nil)
				ts.EXPECT().GenerateToken("user-uuid", "sso").
					Return("new-access-jwt", nil)
				rr.EXPECT().SaveToken(mock.Anything, mock.AnythingOfType("*model.RefreshToken")).
					Return(errors.New("insert failed"))
			},
			wantErr: "save refresh token: insert failed",
		},
		{
			name:         "family revocation fails on replay",
			refreshToken: "valid-refresh-token",
			setupMock: func(ts *mocks.TokenService, rr *mocks.RefreshTokenRepository) {
				revoked := *validRT
				revoked.Revoked = true
				rr.EXPECT().GetByHash(mock.Anything, hashToken("valid-refresh-token")).
					Return(&revoked, nil)
				rr.EXPECT().RevokeByFamilyID(mock.Anything, "family-uuid").
					Return(errors.New("db error"))
			},
			wantErr: "revoke token family: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			tokenSrv := mocks.NewTokenService(t)
			refreshRepo := mocks.NewRefreshTokenRepository(t)
			cache := mocks.NewCacheStore(t)
			emailSender := mocks.NewEmailSender(t)
			tt.setupMock(tokenSrv, refreshRepo)

			svc := New(hasher, tokenSrv, userRepo, refreshRepo, cache, emailSender, time.Minute, time.Hour, zap.NewNop())

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
