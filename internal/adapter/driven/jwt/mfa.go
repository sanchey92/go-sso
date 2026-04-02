package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

const purposeMFAPending = "mfa_pending"

type mfaClaims struct {
	jwt.RegisteredClaims
	Purpose string `json:"purpose"`
}

func (s *Service) GenerateMFAToken(userID string) (string, error) {
	s.mu.RLock()
	currentKey := s.currentKey
	s.mu.RUnlock()

	claims := mfaClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.MFATokenTTL)),
		},
		Purpose: purposeMFAPending,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = currentKey.KID

	signed, err := token.SignedString(currentKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign mfa token: %w", err)
	}
	return signed, nil
}

func (s *Service) ValidateMFAToken(tokenString string) (string, error) {
	s.mu.RLock()
	keys := s.allKeys
	s.mu.RUnlock()

	token, err := jwt.ParseWithClaims(tokenString, &mfaClaims{}, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid")
		}
		key, exists := keys[kid]
		if !exists {
			return nil, fmt.Errorf("unknown kid: %s", key)
		}
		return key.PublicKey, nil
	})
	if err != nil {
		return "", domainerrors.ErrInvalidMFAToken
	}

	claims, ok := token.Claims.(*mfaClaims)
	if !ok || claims.Purpose != purposeMFAPending {
		return "", domainerrors.ErrInvalidMFAToken
	}
	return claims.Subject, nil
}
