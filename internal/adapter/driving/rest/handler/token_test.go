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

func newTokenHandler(t *testing.T) (*TokenHandler, *mocks.TokenService) {
	t.Helper()
	ts := mocks.NewTokenService(t)
	h := NewTokenHandler(ts, zap.NewNop())
	return h, ts
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
			h, ts := newTokenHandler(t)
			tt.mockSetup(ts)

			rec := doRequest(h.Refresh, http.MethodPost, "/api/v1/auth/token/refresh", tt.body)

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
			h, ts := newTokenHandler(t)
			tt.mockSetup(ts)

			rec := doRequest(h.Revoke, http.MethodPost, "/api/v1/auth/token/revoke", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			}
		})
	}
}
