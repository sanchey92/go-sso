package model

import "time"

type UserStatus string

const (
	UserStatusActive  UserStatus = "active"
	UserStatusBlocked UserStatus = "blocked"
	UserStatusDeleted UserStatus = "deleted"
)

type User struct {
	ID            string
	Email         string
	PasswordHash  string
	EmailVerified bool
	MFAEnabled    bool
	MFASecretEnc  []byte
	Status        UserStatus
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
