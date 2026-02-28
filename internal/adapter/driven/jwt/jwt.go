package jwt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

type Claims struct {
	Subject  string
	Issuer   string
	Audience string
}

type Config struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type Service struct {
	cfg        *Config
	currentKey *KeyPair
	allKeys    map[string]*KeyPair
}

func NewService(cfg *Config) (*Service, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	return &Service{
		cfg:        cfg,
		currentKey: kp,
		allKeys:    map[string]*KeyPair{kp.KID: kp},
	}, nil
}

func (s *Service) GenerateToken(userID, audience string) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   userID,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.currentKey.KID
	signed, err := token.SignedString(s.currentKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		key, exists := s.allKeys[kid]
		if !exists {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}
		return key.PublicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domainerrors.ErrTokenExpired
		}
		return nil, fmt.Errorf("parse token: %w", err)
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	var aud string
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}
	return &Claims{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: aud,
	}, nil

}

func (s *Service) GetJWKS() *JWKS {
	keys := make([]JWK, 0, len(s.allKeys))
	for _, kp := range s.allKeys {
		keys = append(keys, JWK{
			KTY: "OKP",
			CRV: "Ed25519",
			KID: kp.KID,
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString(kp.PublicKey),
		})
	}

	return &JWKS{Keys: keys}
}
