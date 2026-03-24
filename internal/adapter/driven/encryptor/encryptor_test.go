package encryptor

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr string
	}{
		{
			name: "valid 32-byte key",
			key:  make([]byte, 32),
		},
		{
			name:    "key too short",
			key:     make([]byte, 16),
			wantErr: "encryption key must be 32 bytes, got 16",
		},
		{
			name:    "key too long",
			key:     make([]byte, 64),
			wantErr: "encryption key must be 32 bytes, got 64",
		},
		{
			name:    "empty key",
			key:     []byte{},
			wantErr: "encryption key must be 32 bytes, got 0",
		},
		{
			name:    "nil key",
			key:     nil,
			wantErr: "encryption key must be 32 bytes, got 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := New(tt.key)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, enc)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, enc)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0xFF, 0xAB, 0xCD},
		},
		{
			name:      "long plaintext",
			plaintext: make([]byte, 10_000),
		},
	}

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := New(key)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, tt.plaintext, ciphertext)

			decrypted, err := enc.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, string(tt.plaintext), string(decrypted))
		})
	}
}

func TestEncrypt_uniqueNonce(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := New(key)
	require.NoError(t, err)

	plaintext := []byte("same input")
	ct1, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	ct2, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "encrypting the same plaintext must produce different ciphertexts")
}

func TestDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := New(key)
	require.NoError(t, err)

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    string
	}{
		{
			name:       "too short ciphertext",
			ciphertext: []byte{0x01, 0x02},
			wantErr:    "ciphertext too short",
		},
		{
			name:       "corrupted ciphertext",
			ciphertext: make([]byte, 100),
			wantErr:    "decrypt:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := enc.Decrypt(tt.ciphertext)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Nil(t, plaintext)
		})
	}
}

func TestDecrypt_wrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	_, err := rand.Read(key1)
	require.NoError(t, err)

	key2 := make([]byte, 32)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	enc1, err := New(key1)
	require.NoError(t, err)

	enc2, err := New(key2)
	require.NoError(t, err)

	ciphertext, err := enc1.Encrypt([]byte("secret"))
	require.NoError(t, err)

	_, err = enc2.Decrypt(ciphertext)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt:")
}
