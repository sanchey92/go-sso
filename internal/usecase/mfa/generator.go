package mfa

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

const alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateRecoveryCodes(count int) (raw []string, hashes []string, err error) {
	raw = make([]string, 0, count)
	hashes = make([]string, 0, count)

	for i := 0; i < count; i++ {
		code, err := generateOneCode()
		if err != nil {
			return nil, nil, fmt.Errorf("generate code %d: %w", i, err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash code %d: %w", i, err)
		}
		raw = append(raw, code)
		hashes = append(hashes, string(hash))
	}

	return raw, hashes, nil
}

func generateOneCode() (string, error) {
	buf := make([]byte, 8)

	for i := range buf {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		if err != nil {
			return "", fmt.Errorf("crypto/rand: %w", err)
		}
		buf[i] = alphanumeric[idx.Int64()]
	}

	return string(buf[:4]) + "-" + string(buf[4:]), nil
}
