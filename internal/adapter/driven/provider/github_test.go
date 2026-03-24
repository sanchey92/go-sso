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

func TestGitHubProvider_GetAuthURL(t *testing.T) {
	p := NewGitHubProvider("gh-client-id", "gh-secret", "http://localhost/callback")

	tests := []struct {
		name     string
		state    string
		verifier string
		check    func(t *testing.T, authURL string)
	}{
		{
			name:     "contains required parameters",
			state:    "random-state-456",
			verifier: "test-verifier-value",
			check: func(t *testing.T, authURL string) {
				u, err := url.Parse(authURL)
				require.NoError(t, err)

				q := u.Query()
				assert.Equal(t, "gh-client-id", q.Get("client_id"))
				assert.Equal(t, "http://localhost/callback", q.Get("redirect_uri"))
				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, "random-state-456", q.Get("state"))
				assert.Equal(t, "S256", q.Get("code_challenge_method"))
				assert.NotEmpty(t, q.Get("code_challenge"))
				assert.Contains(t, q.Get("scope"), "user:email")
				assert.Contains(t, q.Get("scope"), "read:user")
			},
		},
		{
			name:     "uses GitHub auth endpoint",
			state:    "state",
			verifier: "verifier",
			check: func(t *testing.T, authURL string) {
				u, err := url.Parse(authURL)
				require.NoError(t, err)
				assert.Equal(t, "github.com", u.Host)
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

func TestGitHubProvider_ExchangeCode(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name         string
		tokenHandler http.HandlerFunc
		userHandler  http.HandlerFunc
		emailHandler http.HandlerFunc
		wantErr      string
		checkUser    func(t *testing.T, pu *model.ProviderUser)
	}{
		{
			name: "successful exchange with email in profile",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer gh-access-token", r.Header.Get("Authorization"))
				assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(githubUser{
					ID:        12345,
					Login:     "johndoe",
					Name:      "John Doe",
					Email:     "john@github.com",
					AvatarURL: "https://avatars.githubusercontent.com/u/12345",
				})
			},
			checkUser: func(t *testing.T, pu *model.ProviderUser) {
				assert.Equal(t, "12345", pu.ProviderUserID)
				assert.Equal(t, "john@github.com", pu.Email)
				assert.True(t, pu.EmailVerified)
				assert.Equal(t, "John Doe", pu.Name)
				assert.Equal(t, "https://avatars.githubusercontent.com/u/12345", pu.AvatarURL)
			},
		},
		{
			name: "fallback to emails API when profile email is empty",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(githubUser{
					ID:    67890,
					Login: "janedoe",
					Name:  "Jane Doe",
					Email: "",
				})
			},
			emailHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer gh-access-token", r.Header.Get("Authorization"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]githubEmail{
					{Email: "secondary@example.com", Primary: false, Verified: true},
					{Email: "jane@github.com", Primary: true, Verified: true},
				})
			},
			checkUser: func(t *testing.T, pu *model.ProviderUser) {
				assert.Equal(t, "67890", pu.ProviderUserID)
				assert.Equal(t, "jane@github.com", pu.Email)
				assert.True(t, pu.EmailVerified)
				assert.Equal(t, "Jane Doe", pu.Name)
			},
		},
		{
			name: "emails API returns unverified primary",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(githubUser{ID: 111, Email: ""})
			},
			emailHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]githubEmail{
					{Email: "unverified@example.com", Primary: true, Verified: false},
				})
			},
			checkUser: func(t *testing.T, pu *model.ProviderUser) {
				assert.Equal(t, "unverified@example.com", pu.Email)
				assert.False(t, pu.EmailVerified)
			},
		},
		{
			name: "token exchange fails",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "bad_verification_code",
					"error_description": "The code has expired",
				})
			},
			wantErr: "github token exchange",
		},
		{
			name: "user API returns error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"message": "Bad credentials"}`))
			},
			wantErr: "github user",
		},
		{
			name: "emails API returns error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(githubUser{ID: 222, Email: ""})
			},
			emailHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message": "Resource not accessible"}`))
			},
			wantErr: "github emails",
		},
		{
			name: "no primary email found",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "gh-access-token",
					"token_type":   "Bearer",
				})
			},
			userHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(githubUser{ID: 333, Email: ""})
			},
			emailHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]githubEmail{
					{Email: "secondary@example.com", Primary: false, Verified: true},
				})
			},
			wantErr: "no primary email found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenServer := httptest.NewServer(tt.tokenHandler)
			defer tokenServer.Close()

			opts := []GitHubOption{
				WithGitHubEndpoint(oauth2.Endpoint{
					TokenURL:  tokenServer.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				}),
			}

			if tt.userHandler != nil {
				userServer := httptest.NewServer(tt.userHandler)
				defer userServer.Close()
				opts = append(opts, WithGitHubUserURL(userServer.URL))
			}

			if tt.emailHandler != nil {
				emailServer := httptest.NewServer(tt.emailHandler)
				defer emailServer.Close()
				opts = append(opts, WithGitHubEmailsURL(emailServer.URL))
			}

			p := NewGitHubProvider("gh-client-id", "gh-secret", "http://localhost/callback", opts...)

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
