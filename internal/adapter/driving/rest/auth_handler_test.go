package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func newHandler(t *testing.T) (*AuthHandler, *mocks.UserService, *mocks.AuthService, *mocks.TokenService) {
	t.Helper()
	us := mocks.NewUserService(t)
	as := mocks.NewAuthService(t)
	ts := mocks.NewTokenService(t)
	h := NewAuthHandler(us, as, ts, zap.NewNop())
	return h, us, as, ts
}

func doRequest(handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.UserService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "test@example.com", "secret123").
					Return(&model.User{ID: "user-123"}, nil)
			},
			wantStatus: http.StatusCreated,
			wantBody:   `{"user_id":"user-123","message":"user registered successfully"}`,
		},
		{
			name:       "invalid json",
			body:       `{invalid`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "email already exists",
			body: `{"email":"dup@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "dup@example.com", "secret123").
					Return(nil, domainerrors.ErrEmailAlreadyExists)
			},
			wantStatus: http.StatusConflict,
			wantBody:   `{"error":"email already exists","code":"EMAIL_EXISTS"}`,
		},
		{
			name: "validation error",
			body: `{"email":"bad","password":"short"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "bad", "short").
					Return(nil, fmt.Errorf("email: invalid format"))
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"email: invalid format","code":"VALIDATION_ERROR"}`,
		},
		{
			name: "internal error",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "test@example.com", "secret123").
					Return(nil, fmt.Errorf("hash password: %w", fmt.Errorf("something broke")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, us, _, _ := newHandler(t)
			tt.mockSetup(us)

			rec := doRequest(h.Register, http.MethodPost, "/api/v1/auth/register", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.AuthService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.AuthService) {
				svc.EXPECT().Login(mock.Anything, "test@example.com", "secret123").
					Return(&model.TokenPair{
						AccessToken:  "access-tok",
						RefreshToken: "refresh-tok",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"access-tok","refresh_token":"refresh-tok","expires_in":900}`,
		},
		{
			name:       "invalid json",
			body:       `not json`,
			mockSetup:  func(_ *mocks.AuthService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "invalid credentials",
			body: `{"email":"test@example.com","password":"wrong"}`,
			mockSetup: func(svc *mocks.AuthService) {
				svc.EXPECT().Login(mock.Anything, "test@example.com", "wrong").
					Return(nil, domainerrors.ErrInvalidCredentials)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid credentials","code":"INVALID_CREDENTIALS"}`,
		},
		{
			name: "email not verified",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.AuthService) {
				svc.EXPECT().Login(mock.Anything, "test@example.com", "secret123").
					Return(nil, domainerrors.ErrEmailNotVerified)
			},
			wantStatus: http.StatusForbidden,
			wantBody:   `{"error":"email not verified","code":"EMAIL_NOT_VERIFIED"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, as, _ := newHandler(t)
			tt.mockSetup(as)

			rec := doRequest(h.Login, http.MethodPost, "/api/v1/auth/login", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestRefresh(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.TokenService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"refresh_token":"old-token"}`,
			mockSetup: func(svc *mocks.TokenService) {
				svc.EXPECT().RefreshTokens(mock.Anything, "old-token").
					Return(&model.TokenPair{
						AccessToken:  "new-access",
						RefreshToken: "new-refresh",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":900}`,
		},
		{
			name:       "invalid json",
			body:       `{`,
			mockSetup:  func(_ *mocks.TokenService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "token expired",
			body: `{"refresh_token":"expired-token"}`,
			mockSetup: func(svc *mocks.TokenService) {
				svc.EXPECT().RefreshTokens(mock.Anything, "expired-token").
					Return(nil, domainerrors.ErrTokenExpired)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"token expired","code":"TOKEN_EXPIRED"}`,
		},
		{
			name: "token revoked (replay)",
			body: `{"refresh_token":"reused-token"}`,
			mockSetup: func(svc *mocks.TokenService) {
				svc.EXPECT().RefreshTokens(mock.Anything, "reused-token").
					Return(nil, domainerrors.ErrTokenRevoked)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"token revoked","code":"TOKEN_REVOKED"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, ts := newHandler(t)
			tt.mockSetup(ts)

			rec := doRequest(h.Refresh, http.MethodPost, "/api/v1/auth/token/refresh", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestVerifyEmail(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.UserService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"token":"valid-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "valid-token").Return(nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"message":"email verified successfully"}`,
		},
		{
			name:       "invalid json",
			body:       `{bad`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name:       "empty token",
			body:       `{"token":""}`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"token is required","code":"VALIDATION_ERROR"}`,
		},
		{
			name:       "missing token field",
			body:       `{}`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"token is required","code":"VALIDATION_ERROR"}`,
		},
		{
			name: "invalid verification token",
			body: `{"token":"expired-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "expired-token").
					Return(domainerrors.ErrInvalidVerificationToken)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid or expired verification token","code":"INVALID_VERIFICATION_TOKEN"}`,
		},
		{
			name: "internal error",
			body: `{"token":"some-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "some-token").
					Return(fmt.Errorf("update email verified: %w", fmt.Errorf("db error")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, us, _, _ := newHandler(t)
			tt.mockSetup(us)

			rec := doRequest(h.VerifyEmail, http.MethodPost, "/api/v1/auth/email/verify", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestRevoke(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.TokenService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"refresh_token":"tok-to-revoke"}`,
			mockSetup: func(svc *mocks.TokenService) {
				svc.EXPECT().RevokeToken(mock.Anything, "tok-to-revoke").
					Return(nil)
			},
			wantStatus: http.StatusNoContent,
			wantBody:   "",
		},
		{
			name:       "invalid json",
			body:       `[]`,
			mockSetup:  func(_ *mocks.TokenService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "invalid token",
			body: `{"refresh_token":"bad-token"}`,
			mockSetup: func(svc *mocks.TokenService) {
				svc.EXPECT().RevokeToken(mock.Anything, "bad-token").
					Return(domainerrors.ErrInvalidToken)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid token","code":"INVALID_TOKEN"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, ts := newHandler(t)
			tt.mockSetup(ts)

			rec := doRequest(h.Revoke, http.MethodPost, "/api/v1/auth/token/revoke", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			}
		})
	}
}
