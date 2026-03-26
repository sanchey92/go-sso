package auth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/auth/mocks"
)

func TestService_Login(t *testing.T) {
	ctx := t.Context()

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
		setupMock func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, ti *mocks.TokenIssuer, mi *mocks.MFAChallengeIssuer)
		wantErr   string
		check     func(t *testing.T, result *model.LoginResult)
	}{
		{
			name:     "successful login",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, ti *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ti.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(&model.TokenPair{
						AccessToken:  "access-jwt-token",
						RefreshToken: "refresh-token",
						ExpiresIn:    60,
					}, nil)
			},
			check: func(t *testing.T, result *model.LoginResult) {
				require.NotNil(t, result.Tokens)
				assert.Nil(t, result.MFAChallenge)
				assert.Equal(t, "access-jwt-token", result.Tokens.AccessToken)
				assert.Equal(t, "refresh-token", result.Tokens.RefreshToken)
				assert.Equal(t, int64(60), result.Tokens.ExpiresIn)
			},
		},
		{
			name:     "mfa enabled returns challenge",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, mi *mocks.MFAChallengeIssuer) {
				mfaUser := *validUser
				mfaUser.MFAEnabled = true
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&mfaUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				mi.EXPECT().IssueMFAChallenge(mock.Anything, "user-uuid").
					Return(&model.MFAChallenge{MFAToken: "mfa-jwt"}, nil)
			},
			check: func(t *testing.T, result *model.LoginResult) {
				assert.Nil(t, result.Tokens)
				require.NotNil(t, result.MFAChallenge)
				assert.Equal(t, "mfa-jwt", result.MFAChallenge.MFAToken)
			},
		},
		{
			name:     "mfa challenge issuer error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, mi *mocks.MFAChallengeIssuer) {
				mfaUser := *validUser
				mfaUser.MFAEnabled = true
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&mfaUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				mi.EXPECT().IssueMFAChallenge(mock.Anything, "user-uuid").
					Return(nil, errors.New("sign failed"))
			},
			wantErr: "issue mfa challenge: sign failed",
		},
		{
			name:     "user not found returns invalid credentials",
			email:    "nobody@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "nobody@example.com").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "wrong password returns invalid credentials",
			email:    "user@example.com",
			password: "wrongpassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				pv.EXPECT().Verify("wrongpassword", "argon2id-hash").
					Return(false, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "email not verified",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				unverified := *validUser
				unverified.EmailVerified = false
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&unverified, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
			},
			wantErr: domainerrors.ErrEmailNotVerified.Error(),
		},
		{
			name:     "blocked user returns invalid credentials",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				blocked := *validUser
				blocked.Status = model.UserStatusBlocked
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&blocked, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "repository unexpected error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(nil, errors.New("db connection lost"))
			},
			wantErr: "get user by email: db connection lost",
		},
		{
			name:     "hasher verify error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, _ *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(false, errors.New("decode failed"))
			},
			wantErr: "verify password: decode failed",
		},
		{
			name:     "token issuer error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, ti *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ti.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(nil, fmt.Errorf("generate access token: signing failed"))
			},
			wantErr: "generate access token: signing failed",
		},
		{
			name:     "email normalized before lookup",
			email:    "  User@Example.COM  ",
			password: "securepassword",
			setupMock: func(ug *mocks.UserGetter, pv *mocks.PasswordVerifier, ti *mocks.TokenIssuer, _ *mocks.MFAChallengeIssuer) {
				ug.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				pv.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				ti.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(&model.TokenPair{
						AccessToken:  "access-jwt-token",
						RefreshToken: "refresh-token",
						ExpiresIn:    60,
					}, nil)
			},
			check: func(t *testing.T, result *model.LoginResult) {
				require.NotNil(t, result.Tokens)
				assert.NotEmpty(t, result.Tokens.AccessToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			passVerifier := mocks.NewPasswordVerifier(t)
			tokenIssuer := mocks.NewTokenIssuer(t)
			mfaIssuer := mocks.NewMFAChallengeIssuer(t)
			tt.setupMock(userGetter, passVerifier, tokenIssuer, mfaIssuer)

			svc := New(userGetter, passVerifier, tokenIssuer, mfaIssuer, zap.NewNop())

			result, err := svc.Login(ctx, tt.email, tt.password)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}
