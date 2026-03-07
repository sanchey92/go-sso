package handler

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func newAuthHandler(t *testing.T) (*AuthHandler, *mocks.AuthService) {
	t.Helper()
	as := mocks.NewAuthService(t)
	h := NewAuthHandler(as, zap.NewNop())
	return h, as
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
			h, as := newAuthHandler(t)
			tt.mockSetup(as)

			rec := doRequest(h.Login, http.MethodPost, "/api/v1/auth/login", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}
