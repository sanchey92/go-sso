package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func TestService_GenerateMFAToken(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateMFAToken("user-123")

	require.NoError(t, err)
	assert.Equal(t, 3, len(strings.Split(token, ".")))
}

func TestService_ValidateMFAToken_OK(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateMFAToken("user-123")
	require.NoError(t, err)

	userID, err := svc.ValidateMFAToken(token)

	require.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestService_ValidateMFAToken_Expired(t *testing.T) {
	cfg := testConfig()
	cfg.MFATokenTTL = -1 * time.Second

	svc, err := NewService(cfg)
	require.NoError(t, err)

	token, err := svc.GenerateMFAToken("user-123")
	require.NoError(t, err)

	_, err = svc.ValidateMFAToken(token)
	assert.ErrorIs(t, err, domainerrors.ErrInvalidMFAToken)
}

func TestService_ValidateMFAToken_WrongPurpose(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	accessToken, err := svc.GenerateToken("user-123", "my-audience")
	require.NoError(t, err)

	_, err = svc.ValidateMFAToken(accessToken)
	assert.ErrorIs(t, err, domainerrors.ErrInvalidMFAToken)
}

func TestService_ValidateMFAToken_TableDriven(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	validToken, err := svc.GenerateMFAToken("user-456")
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateMFAToken(tt.token)
			if tt.wantErr {
				assert.ErrorIs(t, err, domainerrors.ErrInvalidMFAToken)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestService_ValidateMFAToken_AfterKeyRotation(t *testing.T) {
	svc, err := NewService(testConfig())
	require.NoError(t, err)

	token, err := svc.GenerateMFAToken("user-123")
	require.NoError(t, err)

	require.NoError(t, svc.RotateKey())

	userID, err := svc.ValidateMFAToken(token)

	require.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}
