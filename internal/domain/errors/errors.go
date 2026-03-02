package errors

import "errors"

var (
	ErrTokenExpired       = errors.New("token expired")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)
