package hasher

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testParams() *Config {
	return &Config{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 1,
		KeyLen:      32,
		SaltLen:     16,
	}
}

func TestHasher_Hash(t *testing.T) {
	h := New(testParams())

	hash, err := h.Hash("password123")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
}

func TestHasher_Hash_DifferentSalts(t *testing.T) {
	h := New(testParams())

	hash1, err := h.Hash("password123")
	require.NoError(t, err)

	hash2, err := h.Hash("password123")
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2)
}

func TestHasher_Verify_CorrectPassword(t *testing.T) {
	h := New(testParams())

	hash, err := h.Hash("mypassword")
	require.NoError(t, err)

	match, err := h.Verify("mypassword", hash)
	require.NoError(t, err)

	assert.True(t, match)
}

func TestHasher_Verify_WrongPassword(t *testing.T) {
	h := New(testParams())

	hash, err := h.Hash("mypassword")
	require.NoError(t, err)

	match, err := h.Verify("wrongpassword", hash)
	require.NoError(t, err)

	assert.False(t, match)
}

func TestHasher_Verify_Invalid_Hash(t *testing.T) {
	h := New(testParams())

	_, err := h.Verify("password", "not-a-valid-hash")
	assert.Error(t, err)
}

func TestHasher_Verify_TableDriven(t *testing.T) {
	h := New(testParams())

	hash, err := h.Hash("correntpassword")
	require.NoError(t, err)

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"current password", "correntpassword", true},
		{"wrong password", "wrongpassword", false},
		{"empty password", "", false},
		{"similar password", "correctopasswordD", false},
		{"password with spaces", "   corrnentpassword", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := h.Verify(tt.password, hash)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
}
