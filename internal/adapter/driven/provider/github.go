package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/sanchey92/sso/internal/domain/model"
)

const (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

type GitHubOption func(*GitHubProvider)

type GitHubProvider struct {
	oauth2Cfg  *oauth2.Config
	userURL    string
	emailsURL  string
	httpClient *http.Client
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string, opts ...GitHubOption) *GitHubProvider {
	p := &GitHubProvider{
		oauth2Cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		},
		userURL:    githubUserURL,
		emailsURL:  githubEmailsURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithGitHubUserURL(url string) GitHubOption {
	return func(p *GitHubProvider) {
		p.userURL = url
	}
}

func WithGitHubEmailsURL(url string) GitHubOption {
	return func(p *GitHubProvider) {
		p.emailsURL = url
	}
}

func WithGitHubHTTPClient(client *http.Client) GitHubOption {
	return func(p *GitHubProvider) {
		p.httpClient = client
	}
}

func WithGitHubEndpoint(endpoint oauth2.Endpoint) GitHubOption {
	return func(p *GitHubProvider) {
		p.oauth2Cfg.Endpoint = endpoint
	}
}

func (p *GitHubProvider) GetAuthURL(state, verifier string) string {
	return p.oauth2Cfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
	)
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, verifier string) (*model.ProviderUser, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	token, err := p.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}

	user, err := p.fetchUser(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}

	if user.Email == "" {
		email, verified, err := p.fetchPrimaryEmail(ctx, token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("github emails: %w", err)
		}
		user.Email = email
		user.EmailVerified = verified
	}

	return user, nil
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (p *GitHubProvider) fetchUser(ctx context.Context, accessToken string) (*model.ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github user returned %d: %s", resp.StatusCode, body)
	}

	var info githubUser
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}

	return &model.ProviderUser{
		ProviderUserID: strconv.FormatInt(info.ID, 10),
		Email:          info.Email,
		EmailVerified:  info.Email != "",
		Name:           info.Name,
		AvatarURL:      info.AvatarURL,
	}, nil
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.emailsURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("github emails returned %d: %s", resp.StatusCode, body)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("decode emails: %w", err)
	}

	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}

	return "", false, fmt.Errorf("no primary email found")
}
