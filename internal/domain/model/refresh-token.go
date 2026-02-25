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
