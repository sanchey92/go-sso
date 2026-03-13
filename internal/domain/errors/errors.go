package errors

import "errors"

var (
	ErrTokenExpired             = errors.New("token expired")
	ErrEmailAlreadyExists       = errors.New("email already exists")
	ErrUserNotFound             = errors.New("user not found")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrEmailNotVerified         = errors.New("email not verified")
	ErrInvalidToken             = errors.New("invalid token")
	ErrTokenRevoked             = errors.New("token revoked")
	ErrInvalidVerificationToken = errors.New("invalid or expired token")
	ErrKeyNotFound              = errors.New("key not found")
	ErrInvalidResetToken        = errors.New("invalid or expired reset token")
	ErrOAuthClientNotFound      = errors.New("OAuth client not found")
	ErrInvalidRedirectURI       = errors.New("invalid redirect uri")
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
)
