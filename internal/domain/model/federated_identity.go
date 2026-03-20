package model

import "time"

type FederatedIdentity struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	Email          string
	Name           string
	AvatarURL      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ProviderUser struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
}
