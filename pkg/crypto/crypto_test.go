package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyPKCE(t *testing.T) {
	tests := []struct {
		name          string
		codeVerifier  string
		codeChallenge string
		want          bool
	}{
		{
			name:          "valid verifier matches challenge",
			codeVerifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			want:          true,
		},
		{
			name:          "wrong verifier does not match",
			codeVerifier:  "wrong-verifier-value",
			codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			want:          false,
		},
		{
			name:          "empty verifier",
			codeVerifier:  "",
			codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyPKCE(tt.codeVerifier, tt.codeChallenge)
			assert.Equal(t, tt.want, got)
		})
	}
}
