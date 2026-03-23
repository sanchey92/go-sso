package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/sanchey92/sso/internal/domain/model"
)

func TestGoogleProvider_GetAuthURL(t *testing.T) {
	p := NewGoogleProvider("test-client-id", "test-secret", "http://localhost/callback")

	tests := []struct {
		name     string
		state    string
		verifier string
		check    func(t *testing.T, authURL string)
	}{
		{
			name:     "contains required parameters",
			state:    "random-state-123",
			verifier: "test-verifier-value",
			check: func(t *testing.T, authURL string) {
				u, err := url.Parse(authURL)
				require.NoError(t, err)

				q := u.Query()
				assert.Equal(t, "test-client-id", q.Get("client_id"))
				assert.Equal(t, "http://localhost/callback", q.Get("redirect_uri"))
				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, "random-state-123", q.Get("state"))
				assert.Equal(t, "S256", q.Get("code_challenge_method"))
				assert.NotEmpty(t, q.Get("code_challenge"))
				assert.Contains(t, q.Get("scope"), "openid")
				assert.Contains(t, q.Get("scope"), "email")
				assert.Contains(t, q.Get("scope"), "profile")
			},
		},
		{
			name:     "uses Google auth endpoint",
			state:    "state",
			verifier: "verifier",
			check: func(t *testing.T, authURL string) {
				u, err := url.Parse(authURL)
				require.NoError(t, err)
				assert.Equal(t, "accounts.google.com", u.Host)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := p.GetAuthURL(tt.state, tt.verifier)
			tt.check(t, authURL)
		})
	}
}

func TestGoogleProvider_ExchangeCode(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name         string
		tokenHandler http.HandlerFunc
		userHandler  http.HandlerFunc
		wantErr      string
		checkUser    func(t *testing.T, pu *model.ProviderUser)
	}{
		{
			name: "successful exchange and userinfo",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
				assert.Equal(t, "valid-code", r.FormValue("code"))
				assert.NotEmpty(t, r.FormValue("code_verifier"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "google-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer google-access-token", r.Header.Get("Authorization"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(googleUserInfo{
					Sub:           "google-user-123",
					Email:         "user@gmail.com",
					EmailVerified: true,
					Name:          "John Doe",
					Picture:       "https://lh3.google.com/photo.jpg",
				})
			},
			checkUser: func(t *testing.T, pu *model.ProviderUser) {
				assert.Equal(t, "google-user-123", pu.ProviderUserID)
				assert.Equal(t, "user@gmail.com", pu.Email)
				assert.True(t, pu.EmailVerified)
				assert.Equal(t, "John Doe", pu.Name)
				assert.Equal(t, "https://lh3.google.com/photo.jpg", pu.AvatarURL)
			},
		},
		{
			name: "token exchange fails",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_grant",
					"error_description": "Code has expired",
				})
			},
			wantErr: "google token exchange",
		},
		{
			name: "userinfo returns error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "google-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "invalid_token"}`))
			},
			wantErr: "google userinfo",
		},
		{
			name: "userinfo returns unverified email",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "google-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(googleUserInfo{
					Sub:           "google-user-456",
					Email:         "unverified@gmail.com",
					EmailVerified: false,
					Name:          "Jane",
				})
			},
			checkUser: func(t *testing.T, pu *model.ProviderUser) {
				assert.False(t, pu.EmailVerified)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Мок-сервер для token endpoint
			tokenServer := httptest.NewServer(tt.tokenHandler)
			defer tokenServer.Close()

			// Мок-сервер для userinfo endpoint
			var userInfoURL string
			if tt.userHandler != nil {
				userServer := httptest.NewServer(tt.userHandler)
				defer userServer.Close()
				userInfoURL = userServer.URL
			}

			p := NewGoogleProvider(
				"test-client-id",
				"test-secret",
				"http://localhost/callback",
				WithEndpoint(oauth2.Endpoint{
					TokenURL:  tokenServer.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				}),
				WithUserInfoURL(userInfoURL),
			)

			pu, err := p.ExchangeCode(ctx, "valid-code", "test-verifier")

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			if tt.checkUser != nil {
				tt.checkUser(t, pu)
			}
		})
	}
}
