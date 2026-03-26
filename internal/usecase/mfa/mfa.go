package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

const (
	recoveryCodeCount = 10
	recoveryCodeLen   = 8 // 4 + дефис + 4 = формат XXXX-XXXX
)

type UserGetter interface {
	GetByID(ctx context.Context, userID string) (*model.User, error)
}

type Updater interface {
	UpdateMFA(ctx context.Context, userId string, mfaEnabled bool, mfaSecretEnc []byte) error
}

type RecoveryCodeRepo interface {
	SaveCodes(ctx context.Context, userID string, hashCodes []string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type Service struct {
	userRepo      UserGetter
	mfaUpdater    Updater
	encryptor     Encryptor
	recoveryCodes RecoveryCodeRepo
	issuer        string
	skew          uint
	log           *zap.Logger
}

func New(
	userRepo UserGetter,
	mfaUpdater Updater,
	enc Encryptor,
	rc RecoveryCodeRepo,
	issuer string,
	skew uint,
	log *zap.Logger,
) *Service {
	return &Service{
		userRepo:      userRepo,
		mfaUpdater:    mfaUpdater,
		encryptor:     enc,
		recoveryCodes: rc,
		issuer:        issuer,
		skew:          skew,
		log:           log,
	}
}

func (s *Service) SetupTOTP(ctx context.Context, userID string) (string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	if user.MFAEnabled {
		return "", domainerrors.ErrMFAAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: user.Email,
	})
	if err != nil {
		return "", fmt.Errorf("generate totp key: %w", err)
	}

	encrypted, err := s.encryptor.Encrypt([]byte(key.Secret()))
	if err != nil {
		return "", fmt.Errorf("encrypt totp secret: %w", err)
	}

	if err := s.mfaUpdater.UpdateMFA(ctx, userID, false, encrypted); err != nil {
		return "", fmt.Errorf("update mfa: %w", err)
	}

	s.log.Info("totp setup initiated", zap.String("user_id", userID))
	return key.URL(), nil
}

func (s *Service) VerifySetup(ctx context.Context, userID, code string) ([]string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user.MFAEnabled {
		return nil, domainerrors.ErrMFAAlreadyEnabled
	}
	if user.MFASecretEnc == nil {
		return nil, domainerrors.ErrMFANotEnabled
	}

	secret, err := s.encryptor.Decrypt(user.MFASecretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt totp secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, string(secret), time.Now(), totp.ValidateOpts{
		Skew:   s.skew,
		Digits: otp.DigitsSix,
	})
	if err != nil || !valid {
		return nil, domainerrors.ErrInvalidTOTPCode
	}

	if err := s.mfaUpdater.UpdateMFA(ctx, userID, true, user.MFASecretEnc); err != nil {
		return nil, fmt.Errorf("enable fma: %w", err)
	}

	rawCodes, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, fmt.Errorf("generate recovery codes: %w", err)
	}

	if err := s.recoveryCodes.DeleteByUserID(ctx, userID); err != nil {
		return nil, fmt.Errorf("delete old recovery codes: %w", err)
	}

	if err := s.recoveryCodes.SaveCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("save recovery codes: %w", err)
	}

	s.log.Info("mfa setup verified", zap.String("user_id", userID))
	return rawCodes, nil
}
