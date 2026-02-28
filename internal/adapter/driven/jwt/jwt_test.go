package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func testConfig() *Config {
	return &Config{
		Issuer:          "test-issuer",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
}

func TestNewService(t *testing.T) {
	svc, err := NewService(testConfig())

	require.NoError(t, err)
	assert.NotNil(t, svc.currentKey)
	assert.Len(t, svc.allKeys, 1)
}

func TestService_GenerateToken(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateToken("user-123", "my-app")

	require.NoError(t, err)
	assert.Equal(t, 3, len(strings.Split(token, ".")))
}

func TestService_ValidateToken_OK(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateToken("user-123", "my-app")
	require.NoError(t, err)

	claims, err := svc.ValidateToken(token)

	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.Equal(t, "my-app", claims.Audience)
}

func TestService_ValidateToken_Tampered(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateToken("user-123", "my-app")
	require.NoError(t, err)

	tampered := token[:len(token)-4] + "XXXX"

	_, err = svc.ValidateToken(tampered)
	assert.Error(t, err)
}

func TestService_ValidateToken_Expired(t *testing.T) {
	cfg := testConfig()
	cfg.AccessTokenTTL = -1 * time.Second

	svc, err := NewService(cfg)
	require.NoError(t, err)

	token, err := svc.GenerateToken("user-123", "my-app")
	require.NoError(t, err)

	_, err = svc.ValidateToken(token)
	assert.ErrorIs(t, err, domainerrors.ErrTokenExpired)
}

func TestService_ValidateToken_InvalidString(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	_, err = svc.ValidateToken("not-a-valid-token")
	assert.Error(t, err)
}

func TestService_ValidateToken_TableDriven(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	validToken, err := svc.GenerateToken("user-456", "app-2")
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid token", validToken, false},
		{"empty string", "", true},
		{"random string", "abc.def.ghi", true},
		{"tampered token", validToken[:len(validToken)-4] + "XXXX", true},
		{"missing segment", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxIn0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestService_GetJWKS(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	jwks := svc.GetJWKS()

	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "OKP", jwks.Keys[0].KTY)
	assert.Equal(t, "Ed25519", jwks.Keys[0].CRV)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.Equal(t, svc.currentKey.KID, jwks.Keys[0].KID)
	assert.NotEmpty(t, jwks.Keys[0].X)
}

func TestGenerateKID_Deterministic(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	kid1 := GenerateKID(kp.PublicKey)
	kid2 := GenerateKID(kp.PublicKey)

	assert.Equal(t, kid1, kid2)
	assert.Len(t, kid1, 16)
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, err := GenerateKeyPair()
	require.NoError(t, err)

	kp2, err := GenerateKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, kp1.KID, kp2.KID)
}
