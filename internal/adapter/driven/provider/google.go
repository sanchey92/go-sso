package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sanchey92/sso/internal/domain/model"
)

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"

type GoogleOption func(*GoogleProvider)

type GoogleProvider struct {
	oauth2Cfg   *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string, opts ...GoogleOption) *GoogleProvider {
	p := &GoogleProvider{
		oauth2Cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		userInfoURL: googleUserInfoURL,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithUserInfoURL(url string) GoogleOption {
	return func(p *GoogleProvider) {
		p.userInfoURL = url
	}
}

func WithHTTPClient(client *http.Client) GoogleOption {
	return func(p *GoogleProvider) {
		p.httpClient = client
	}
}

func WithEndpoint(endpoint oauth2.Endpoint) GoogleOption {
	return func(p *GoogleProvider) {
		p.oauth2Cfg.Endpoint = endpoint
	}
}

func (p *GoogleProvider) GetAuthURL(state, verifier string) string {
	return p.oauth2Cfg.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, verifier string) (*model.ProviderUser, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	token, err := p.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}

	userInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	return userInfo, nil
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (p *GoogleProvider) fetchUserInfo(ctx context.Context, accessToken string) (*model.ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req) //nolint:gosec // URL from const, not user input
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:gosec // error in error path, best-effort read
		return nil, fmt.Errorf("google userinfo returned %d: %s", resp.StatusCode, body)
	}

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &model.ProviderUser{
		ProviderUserID: info.Sub,
		Email:          info.Email,
		EmailVerified:  info.EmailVerified,
		Name:           info.Name,
		AvatarURL:      info.Picture,
	}, nil
}
