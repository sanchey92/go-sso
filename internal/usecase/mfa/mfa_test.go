package mfa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/internal/usecase/mfa/mocks"
)

const testIssuer = "test-issuer"

func generateTOTPSecret(t *testing.T) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      testIssuer,
		AccountName: "user@example.com",
	})
	require.NoError(t, err)
	return key.Secret()
}

func generateValidCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

func TestService_SetupTOTP(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	tests := []struct {
		name      string
		setupMock func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor)
		wantErr   string
		check     func(t *testing.T, uri string)
	}{
		{
			name: "successful setup returns otpauth URI",
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, Email: "user@example.com", MFAEnabled: false}, nil)
				enc.EXPECT().Encrypt(mock.Anything).
					Return([]byte("encrypted-secret"), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, []byte("encrypted-secret")).
					Return(nil)
			},
			check: func(t *testing.T, uri string) {
				assert.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
				assert.Contains(t, uri, "user@example.com")
			},
		},
		{
			name: "user not found",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrUserNotFound.Error(),
		},
		{
			name: "mfa already enabled",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, Email: "user@example.com", MFAEnabled: true}, nil)
			},
			wantErr: domainerrors.ErrMFAAlreadyEnabled.Error(),
		},
		{
			name: "encrypt error",
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, Email: "user@example.com", MFAEnabled: false}, nil)
				enc.EXPECT().Encrypt(mock.Anything).
					Return(nil, errors.New("encrypt failed"))
			},
			wantErr: "encrypt totp secret: encrypt failed",
		},
		{
			name: "update mfa error",
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, Email: "user@example.com", MFAEnabled: false}, nil)
				enc.EXPECT().Encrypt(mock.Anything).
					Return([]byte("encrypted-secret"), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, []byte("encrypted-secret")).
					Return(errors.New("db error"))
			},
			wantErr: "update mfa: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			updater := mocks.NewUpdater(t)
			encryptor := mocks.NewEncryptor(t)
			rc := mocks.NewRecoveryCodeRepo(t)
			rr := mocks.NewRecoveryReader(t)
			tt.setupMock(userGetter, updater, encryptor)

			svc := New(userGetter, updater, encryptor, rc, rr, testIssuer, 1, zap.NewNop())

			uri, err := svc.SetupTOTP(ctx, userID)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, uri)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, uri)

			if tt.check != nil {
				tt.check(t, uri)
			}
		})
	}
}

func TestService_VerifySetup(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	totpSecret := generateTOTPSecret(t)
	encryptedSecret := []byte("encrypted-secret")

	tests := []struct {
		name      string
		codeFunc  func(t *testing.T) string
		setupMock func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo)
		wantErr   string
		check     func(t *testing.T, codes []string)
	}{
		{
			name:     "successful verify returns 10 recovery codes",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						Email:        "user@example.com",
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, true, encryptedSecret).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(nil)
				rc.EXPECT().SaveCodes(mock.Anything, userID, mock.Anything).
					Return(nil)
			},
			check: func(t *testing.T, codes []string) {
				require.Len(t, codes, 10)
				for _, code := range codes {
					assert.Len(t, code, 9) // XXXX-XXXX = 9 chars
					assert.Equal(t, '-', rune(code[4]))
				}
			},
		},
		{
			name:     "user not found",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrUserNotFound.Error(),
		},
		{
			name:     "mfa already enabled",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
			},
			wantErr: domainerrors.ErrMFAAlreadyEnabled.Error(),
		},
		{
			name:     "mfa secret not set",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: nil,
					}, nil)
			},
			wantErr: domainerrors.ErrMFANotEnabled.Error(),
		},
		{
			name:     "decrypt error",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, enc *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return(nil, errors.New("decrypt failed"))
			},
			wantErr: "decrypt totp secret: decrypt failed",
		},
		{
			name:     "invalid totp code",
			codeFunc: func(_ *testing.T) string { return "000000" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, enc *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
			},
			wantErr: domainerrors.ErrInvalidTOTPCode.Error(),
		},
		{
			name:     "update mfa error",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, _ *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, true, encryptedSecret).
					Return(errors.New("db error"))
			},
			wantErr: "enable mfa: db error",
		},
		{
			name:     "delete old codes error",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, true, encryptedSecret).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(errors.New("db error"))
			},
			wantErr: "delete old recovery codes: db error",
		},
		{
			name:     "save codes error",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   false,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, true, encryptedSecret).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(nil)
				rc.EXPECT().SaveCodes(mock.Anything, userID, mock.Anything).
					Return(errors.New("db error"))
			},
			wantErr: "save recovery codes: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			updater := mocks.NewUpdater(t)
			encryptor := mocks.NewEncryptor(t)
			rcRepo := mocks.NewRecoveryCodeRepo(t)
			rr := mocks.NewRecoveryReader(t)
			tt.setupMock(userGetter, updater, encryptor, rcRepo)

			svc := New(userGetter, updater, encryptor, rcRepo, rr, testIssuer, 1, zap.NewNop())

			code := tt.codeFunc(t)
			codes, err := svc.VerifySetup(ctx, userID, code)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, codes)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, codes)

			if tt.check != nil {
				tt.check(t, codes)
			}
		})
	}
}

func TestService_VerifySetup_recovery_codes_are_bcrypt_hashes(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	totpSecret := generateTOTPSecret(t)
	encryptedSecret := []byte("encrypted-secret")

	userGetter := mocks.NewUserGetter(t)
	updater := mocks.NewUpdater(t)
	encryptor := mocks.NewEncryptor(t)
	rcRepo := mocks.NewRecoveryCodeRepo(t)

	userGetter.EXPECT().GetByID(mock.Anything, userID).
		Return(&model.User{
			ID:           userID,
			Email:        "user@example.com",
			MFAEnabled:   false,
			MFASecretEnc: encryptedSecret,
		}, nil)
	encryptor.EXPECT().Decrypt(encryptedSecret).
		Return([]byte(totpSecret), nil)
	updater.EXPECT().UpdateMFA(mock.Anything, userID, true, encryptedSecret).
		Return(nil)
	rcRepo.EXPECT().DeleteByUserID(mock.Anything, userID).
		Return(nil)

	var savedHashes []string
	rcRepo.EXPECT().SaveCodes(mock.Anything, userID, mock.Anything).
		Run(func(_ context.Context, _ string, hashes []string) {
			savedHashes = hashes
		}).
		Return(nil)

	rr := mocks.NewRecoveryReader(t)
	svc := New(userGetter, updater, encryptor, rcRepo, rr, testIssuer, 1, zap.NewNop())

	validCode := generateValidCode(t, totpSecret)
	rawCodes, err := svc.VerifySetup(ctx, userID, validCode)
	require.NoError(t, err)
	require.Len(t, rawCodes, 10)
	require.Len(t, savedHashes, 10)

	for i, raw := range rawCodes {
		err := bcrypt.CompareHashAndPassword([]byte(savedHashes[i]), []byte(raw))
		assert.NoError(t, err, "recovery code %d hash mismatch", i)
	}
}

func TestService_VerifyTOTP(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	totpSecret := generateTOTPSecret(t)
	encryptedSecret := []byte("encrypted-secret")

	tests := []struct {
		name      string
		codeFunc  func(t *testing.T) string
		setupMock func(ug *mocks.UserGetter, enc *mocks.Encryptor)
		wantErr   string
	}{
		{
			name:     "correct code returns user",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						Email:        "user@example.com",
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
			},
		},
		{
			name:     "wrong code",
			codeFunc: func(_ *testing.T) string { return "000000" },
			setupMock: func(ug *mocks.UserGetter, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
			},
			wantErr: domainerrors.ErrInvalidTOTPCode.Error(),
		},
		{
			name:     "mfa not enabled",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, MFAEnabled: false}, nil)
			},
			wantErr: domainerrors.ErrMFANotEnabled.Error(),
		},
		{
			name:     "user not found",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(nil, domainerrors.ErrUserNotFound)
			},
			wantErr: domainerrors.ErrUserNotFound.Error(),
		},
		{
			name:     "decrypt error",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, enc *mocks.Encryptor) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return(nil, errors.New("decrypt failed"))
			},
			wantErr: "decrypt mfa secret: decrypt failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			updater := mocks.NewUpdater(t)
			encryptor := mocks.NewEncryptor(t)
			rcRepo := mocks.NewRecoveryCodeRepo(t)
			rr := mocks.NewRecoveryReader(t)
			tt.setupMock(userGetter, encryptor)

			svc := New(userGetter, updater, encryptor, rcRepo, rr, testIssuer, 1, zap.NewNop())

			code := tt.codeFunc(t)
			user, err := svc.VerifyTOTP(ctx, userID, code)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, user)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, user)
			assert.Equal(t, userID, user.ID)
		})
	}
}

func TestService_VerifyRecoveryCode(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	rawCode := "ABCD-1234"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawCode), bcrypt.DefaultCost)
	require.NoError(t, err)

	tests := []struct {
		name      string
		code      string
		setupMock func(rr *mocks.RecoveryReader)
		wantErr   string
	}{
		{
			name: "valid unused code — second code matches",
			code: rawCode,
			setupMock: func(rr *mocks.RecoveryReader) {
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{
						{ID: "code-1", CodeHash: "non-matching-hash", Used: false},
						{ID: "code-2", CodeHash: string(hash), Used: false},
					}, nil)
				rr.EXPECT().MarkUsed(mock.Anything, "code-2").Return(nil)
			},
		},
		{
			name: "no match",
			code: "WRONG-CODE",
			setupMock: func(rr *mocks.RecoveryReader) {
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{
						{ID: "code-1", CodeHash: string(hash), Used: false},
					}, nil)
			},
			wantErr: domainerrors.ErrRecoveryCodeNotFound.Error(),
		},
		{
			name: "all used — empty list",
			code: rawCode,
			setupMock: func(rr *mocks.RecoveryReader) {
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{}, nil)
			},
			wantErr: domainerrors.ErrRecoveryCodeNotFound.Error(),
		},
		{
			name: "get unused error",
			code: rawCode,
			setupMock: func(rr *mocks.RecoveryReader) {
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return(nil, errors.New("db error"))
			},
			wantErr: "get unused recovery codes: db error",
		},
		{
			name: "mark used error",
			code: rawCode,
			setupMock: func(rr *mocks.RecoveryReader) {
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{
						{ID: "code-1", CodeHash: string(hash), Used: false},
					}, nil)
				rr.EXPECT().MarkUsed(mock.Anything, "code-1").
					Return(errors.New("db error"))
			},
			wantErr: "mark recovery code used: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			updater := mocks.NewUpdater(t)
			encryptor := mocks.NewEncryptor(t)
			rcRepo := mocks.NewRecoveryCodeRepo(t)
			rr := mocks.NewRecoveryReader(t)
			tt.setupMock(rr)

			svc := New(userGetter, updater, encryptor, rcRepo, rr, testIssuer, 1, zap.NewNop())

			err := svc.VerifyRecoveryCode(ctx, userID, tt.code)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestService_DisableTOTP(t *testing.T) {
	ctx := t.Context()
	const userID = "user-123"

	totpSecret := generateTOTPSecret(t)
	encryptedSecret := []byte("encrypted-secret")

	recoveryCode := "ABCD-1234"
	recoveryHash, err := bcrypt.GenerateFromPassword([]byte(recoveryCode), bcrypt.DefaultCost)
	require.NoError(t, err)

	tests := []struct {
		name      string
		codeFunc  func(t *testing.T) string
		setupMock func(
			ug *mocks.UserGetter,
			upd *mocks.Updater,
			enc *mocks.Encryptor,
			rc *mocks.RecoveryCodeRepo,
			rr *mocks.RecoveryReader,
		)
		wantErr string
	}{
		{
			name:     "via valid TOTP code",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo, _ *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, ([]byte)(nil)).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(nil)
			},
		},
		{
			name:     "via recovery code — TOTP fails, recovery succeeds",
			codeFunc: func(_ *testing.T) string { return recoveryCode },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo, rr *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				// "ABCD-1234" fails TOTP (wrong length) → ErrInvalidTOTPCode → fallback to recovery
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{
						{ID: "code-1", CodeHash: string(recoveryHash), Used: false},
					}, nil)
				rr.EXPECT().MarkUsed(mock.Anything, "code-1").Return(nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, ([]byte)(nil)).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(nil)
			},
		},
		{
			name:     "both fail — TOTP invalid, no matching recovery code",
			codeFunc: func(_ *testing.T) string { return "WRONG-CODE" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, enc *mocks.Encryptor, _ *mocks.RecoveryCodeRepo, rr *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				rr.EXPECT().GetUnusedByUserID(mock.Anything, userID).
					Return([]model.RecoveryCode{}, nil)
			},
			wantErr: domainerrors.ErrRecoveryCodeNotFound.Error(),
		},
		{
			name:     "mfa not enabled — no fallback to recovery",
			codeFunc: func(_ *testing.T) string { return "123456" },
			setupMock: func(ug *mocks.UserGetter, _ *mocks.Updater, _ *mocks.Encryptor, _ *mocks.RecoveryCodeRepo, _ *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{ID: userID, MFAEnabled: false}, nil)
			},
			wantErr: domainerrors.ErrMFANotEnabled.Error(),
		},
		{
			name:     "update mfa error",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, _ *mocks.RecoveryCodeRepo, _ *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, ([]byte)(nil)).
					Return(errors.New("db error"))
			},
			wantErr: "disable mfa: db error",
		},
		{
			name:     "delete codes error",
			codeFunc: func(t *testing.T) string { return generateValidCode(t, totpSecret) },
			setupMock: func(ug *mocks.UserGetter, upd *mocks.Updater, enc *mocks.Encryptor, rc *mocks.RecoveryCodeRepo, _ *mocks.RecoveryReader) {
				ug.EXPECT().GetByID(mock.Anything, userID).
					Return(&model.User{
						ID:           userID,
						MFAEnabled:   true,
						MFASecretEnc: encryptedSecret,
					}, nil)
				enc.EXPECT().Decrypt(encryptedSecret).
					Return([]byte(totpSecret), nil)
				upd.EXPECT().UpdateMFA(mock.Anything, userID, false, ([]byte)(nil)).
					Return(nil)
				rc.EXPECT().DeleteByUserID(mock.Anything, userID).
					Return(errors.New("db error"))
			},
			wantErr: "delete recovery codes: db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userGetter := mocks.NewUserGetter(t)
			updater := mocks.NewUpdater(t)
			encryptor := mocks.NewEncryptor(t)
			rcRepo := mocks.NewRecoveryCodeRepo(t)
			rr := mocks.NewRecoveryReader(t)
			tt.setupMock(userGetter, updater, encryptor, rcRepo, rr)

			svc := New(userGetter, updater, encryptor, rcRepo, rr, testIssuer, 1, zap.NewNop())

			code := tt.codeFunc(t)
			err := svc.DisableTOTP(ctx, userID, code)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}
