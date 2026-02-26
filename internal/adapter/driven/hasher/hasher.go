package hasher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Config struct {
	Memory      uint32 // kb
	Iterations  uint32
	Parallelism uint8
	KeyLen      uint32
	SaltLen     uint32
}

type Hasher struct {
	cfg *Config
}

func DefaultConfig() *Config {
	return &Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32,
		SaltLen:     16,
	}
}

func New(cfg *Config) *Hasher {
	return &Hasher{cfg: cfg}
}

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.cfg.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.cfg.Iterations,
		h.cfg.Memory,
		h.cfg.Parallelism,
		h.cfg.KeyLen,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	result := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.cfg.Memory,
		h.cfg.Iterations,
		h.cfg.Parallelism,
		encodedSalt,
		encodedHash,
	)

	return result, nil
}

func (h *Hasher) Verify(password, encodedHash string) (bool, error) {
	cfg, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Iterations,
		cfg.Memory,
		cfg.Parallelism,
		cfg.KeyLen,
	)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (*Config, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("incompatible argon2 version: %d", version)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible argon2 version: %d", version)
	}

	cfg := &Config{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cfg.Memory, &cfg.Iterations, &cfg.Parallelism); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash salt: %w", err)
	}
	if len(salt) > math.MaxUint32 {
		return nil, nil, nil, fmt.Errorf("salt length exceeds uint32")
	}
	cfg.SaltLen = uint32(len(salt)) //nolint:gosec // length checked above

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash: %w", err)
	}
	if len(hash) > math.MaxUint32 {
		return nil, nil, nil, fmt.Errorf("hash length exceeds uint32")
	}
	cfg.KeyLen = uint32(len(hash)) //nolint:gosec // length checked above

	return cfg, salt, hash, nil
}
