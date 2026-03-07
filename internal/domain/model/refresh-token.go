package model

import "time"

type RefreshToken struct {
	ID        string
	TokenHash string
	UserID    string
	ClientID  string
	FamilyID  string
	Scopes    []string
	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}
