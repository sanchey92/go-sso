package model

import "time"

type OAuthClient struct {
	ID             string
	SecretHash     string
	Name           string
	RedirectURIs   []string
	AllowedScopes  []string
	IsConfidential bool
	CreatedAt      time.Time
}
