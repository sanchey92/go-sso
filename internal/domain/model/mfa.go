package model

import "time"

type RecoveryCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt time.Time
}

type MFAChallenge struct {
	MFAToken string
}

type LoginResult struct {
	Tokens       *TokenPair
	MFAChallenge *MFAChallenge
}
