package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type KeyPair struct {
	KID        string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func GenerateKID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:8])
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &KeyPair{
		KID:        GenerateKID(pub),
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	KID string `json:"kid"`
	Use string `json:"use"`
	X   string `json:"x"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
