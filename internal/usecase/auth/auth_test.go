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

type authMocks struct {
	userGetter   *mocks.UserGetter
	passVerifier *mocks.PasswordVerifier
	tokenIssuer  *mocks.TokenIssuer
	mfaIssuer    *mocks.MFAChallengeIssuer
	mfaValidator *mocks.MFATokenValidator
	totpVerifier *mocks.TOTPVerifier
	recoveryVer  *mocks.RecoveryVerifier
}

func newAuthMocks(t *testing.T) *authMocks {
	return &authMocks{
		userGetter:   mocks.NewUserGetter(t),
		passVerifier: mocks.NewPasswordVerifier(t),
		tokenIssuer:  mocks.NewTokenIssuer(t),
		mfaIssuer:    mocks.NewMFAChallengeIssuer(t),
		mfaValidator: mocks.NewMFATokenValidator(t),
		totpVerifier: mocks.NewTOTPVerifier(t),
		recoveryVer:  mocks.NewRecoveryVerifier(t),
	}
}

func (m *authMocks) newService() *Service {
	return New(
		m.userGetter,
		m.passVerifier,
		m.tokenIssuer,
		m.mfaIssuer,
		m.mfaValidator,
		m.totpVerifier,
		m.recoveryVer,
		zap.NewNop(),
	)
}

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
		setupMock func(m *authMocks)
		wantErr   string
		check     func(t *testing.T, result *model.LoginResult)
	}{
		{
			name:     "successful login",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
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
			setupMock: func(m *authMocks) {
				mfaUser := *validUser
				mfaUser.MFAEnabled = true
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&mfaUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				m.mfaIssuer.EXPECT().IssueMFAChallenge(mock.Anything, "user-uuid").
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
			setupMock: func(m *authMocks) {
				mfaUser := *validUser
				mfaUser.MFAEnabled = true
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&mfaUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				m.mfaIssuer.EXPECT().IssueMFAChallenge(mock.Anything, "user-uuid").
					Return(nil, errors.New("sign failed"))
			},
			wantErr: "issue mfa challenge: sign failed",
		},
		{
			name:     "user not found returns invalid credentials",
			email:    "nobody@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "nobody@example.com").
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "wrong password returns invalid credentials",
			email:    "user@example.com",
			password: "wrongpassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				m.passVerifier.EXPECT().Verify("wrongpassword", "argon2id-hash").
					Return(false, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "email not verified",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				unverified := *validUser
				unverified.EmailVerified = false
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&unverified, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
			},
			wantErr: domainerrors.ErrEmailNotVerified.Error(),
		},
		{
			name:     "blocked user returns invalid credentials",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				blocked := *validUser
				blocked.Status = model.UserStatusBlocked
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(&blocked, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
			},
			wantErr: domainerrors.ErrInvalidCredentials.Error(),
		},
		{
			name:     "repository unexpected error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(nil, errors.New("db connection lost"))
			},
			wantErr: "get user by email: db connection lost",
		},
		{
			name:     "hasher verify error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(false, errors.New("decode failed"))
			},
			wantErr: "verify password: decode failed",
		},
		{
			name:     "token issuer error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(nil, fmt.Errorf("generate access token: signing failed"))
			},
			wantErr: "generate access token: signing failed",
		},
		{
			name:     "email normalized before lookup",
			email:    "  User@Example.COM  ",
			password: "securepassword",
			setupMock: func(m *authMocks) {
				m.userGetter.EXPECT().GetByEmail(mock.Anything, "user@example.com").
					Return(validUser, nil)
				m.passVerifier.EXPECT().Verify("securepassword", "argon2id-hash").
					Return(true, nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
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
			m := newAuthMocks(t)
			tt.setupMock(m)

			svc := m.newService()
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

func TestService_CompleteMFALogin(t *testing.T) {
	ctx := t.Context()

	tokenPair := &model.TokenPair{
		AccessToken:  "access-jwt-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    60,
	}

	tests := []struct {
		name      string
		mfaToken  string
		totpCode  string
		setupMock func(m *authMocks)
		wantErr   string
		check     func(t *testing.T, pair *model.TokenPair)
	}{
		{
			name:     "successful mfa login",
			mfaToken: "valid-mfa-jwt",
			totpCode: "123456",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.totpVerifier.EXPECT().VerifyTOTP(mock.Anything, "user-uuid", "123456").
					Return(&model.User{ID: "user-uuid"}, nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(tokenPair, nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "access-jwt-token", pair.AccessToken)
				assert.Equal(t, "refresh-token", pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn)
			},
		},
		{
			name:     "invalid mfa token",
			mfaToken: "expired-mfa-jwt",
			totpCode: "123456",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("expired-mfa-jwt").
					Return("", domainerrors.ErrInvalidMFAToken)
			},
			wantErr: "validate mfa token",
		},
		{
			name:     "invalid totp code",
			mfaToken: "valid-mfa-jwt",
			totpCode: "000000",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.totpVerifier.EXPECT().VerifyTOTP(mock.Anything, "user-uuid", "000000").
					Return(nil, domainerrors.ErrInvalidTOTPCode)
			},
			wantErr: "verify mfa",
		},
		{
			name:     "token issuer error after mfa",
			mfaToken: "valid-mfa-jwt",
			totpCode: "123456",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.totpVerifier.EXPECT().VerifyTOTP(mock.Anything, "user-uuid", "123456").
					Return(&model.User{ID: "user-uuid"}, nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(nil, errors.New("signing failed"))
			},
			wantErr: "issue token pair: signing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newAuthMocks(t)
			tt.setupMock(m)

			svc := m.newService()
			pair, err := svc.CompleteMFALogin(ctx, tt.mfaToken, tt.totpCode)

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

func TestService_CompleteMFARecovery(t *testing.T) {
	ctx := t.Context()

	tokenPair := &model.TokenPair{
		AccessToken:  "access-jwt-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    60,
	}

	tests := []struct {
		name         string
		mfaToken     string
		recoveryCode string
		setupMock    func(m *authMocks)
		wantErr      string
		check        func(t *testing.T, pair *model.TokenPair)
	}{
		{
			name:         "successful recovery login",
			mfaToken:     "valid-mfa-jwt",
			recoveryCode: "ABCD-1234-EFGH",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.recoveryVer.EXPECT().VerifyRecoveryCode(mock.Anything, "user-uuid", "ABCD-1234-EFGH").
					Return(nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(tokenPair, nil)
			},
			check: func(t *testing.T, pair *model.TokenPair) {
				assert.Equal(t, "access-jwt-token", pair.AccessToken)
				assert.Equal(t, "refresh-token", pair.RefreshToken)
				assert.Equal(t, int64(60), pair.ExpiresIn)
			},
		},
		{
			name:         "invalid mfa token",
			mfaToken:     "expired-mfa-jwt",
			recoveryCode: "ABCD-1234-EFGH",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("expired-mfa-jwt").
					Return("", domainerrors.ErrInvalidMFAToken)
			},
			wantErr: "validate mfa token",
		},
		{
			name:         "recovery code not found",
			mfaToken:     "valid-mfa-jwt",
			recoveryCode: "WRONG-CODE",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.recoveryVer.EXPECT().VerifyRecoveryCode(mock.Anything, "user-uuid", "WRONG-CODE").
					Return(domainerrors.ErrRecoveryCodeNotFound)
			},
			wantErr: "verify recovery code",
		},
		{
			name:         "recovery code already used",
			mfaToken:     "valid-mfa-jwt",
			recoveryCode: "USED-CODE",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.recoveryVer.EXPECT().VerifyRecoveryCode(mock.Anything, "user-uuid", "USED-CODE").
					Return(domainerrors.ErrRecoveryCodeUsed)
			},
			wantErr: "verify recovery code",
		},
		{
			name:         "token issuer error after recovery",
			mfaToken:     "valid-mfa-jwt",
			recoveryCode: "ABCD-1234-EFGH",
			setupMock: func(m *authMocks) {
				m.mfaValidator.EXPECT().ValidateMFAToken("valid-mfa-jwt").
					Return("user-uuid", nil)
				m.recoveryVer.EXPECT().VerifyRecoveryCode(mock.Anything, "user-uuid", "ABCD-1234-EFGH").
					Return(nil)
				m.tokenIssuer.EXPECT().IssueTokenPair(mock.Anything, "user-uuid", "", mock.Anything).
					Return(nil, errors.New("signing failed"))
			},
			wantErr: "issue token pair: signing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newAuthMocks(t)
			tt.setupMock(m)

			svc := m.newService()
			pair, err := svc.CompleteMFARecovery(ctx, tt.mfaToken, tt.recoveryCode)

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
