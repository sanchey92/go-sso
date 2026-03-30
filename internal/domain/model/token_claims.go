package model

import "time"

type TokenClaims struct {
	Subject   string
	Issuer    string
	Audience  string
	ExpiresAt time.Time
	IssuedAt  time.Time
}
