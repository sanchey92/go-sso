package mfa

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func TestVerifyTOTP(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(c *mocks.Completer)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"mfa_token":"mfa-jwt","code":"123456"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFALogin(mock.Anything, "mfa-jwt", "123456").
					Return(&model.TokenPair{
						AccessToken:  "access-tok",
						RefreshToken: "refresh-tok",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"access-tok","refresh_token":"refresh-tok","expires_in":900,"token_type":"Bearer"}`,
		},
		{
			name:       "invalid json",
			body:       "{bad",
			mockSetup:  func(c *mocks.Completer) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "invalid totp code",
			body: `{"mfa_token":"mfa-jwt","code":"wrong"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFALogin(mock.Anything, "mfa-jwt", "wrong").
					Return(nil, domainerrors.ErrInvalidTOTPCode)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid totp code","code":"INVALID_TOTP_CODE"}`,
		},
		{
			name: "invalid mfa token",
			body: `{"mfa_token":"expired","code":"123456"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFALogin(mock.Anything, "expired", "123456").
					Return(nil, domainerrors.ErrInvalidMFAToken)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid or expired mfa token","code":"INVALID_MFA_TOKEN"}`,
		},
		{
			name: "mfa not enabled",
			body: `{"mfa_token":"mfa-jwt","code":"123456"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFALogin(mock.Anything, "mfa-jwt", "123456").
					Return(nil, domainerrors.ErrMFANotEnabled)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"mfa not enabled","code":"MFA_NOT_ENABLED"}`,
		},
		{
			name: "internal error",
			body: `{"mfa_token":"mfa-jwt","code":"123456"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFALogin(mock.Anything, "mfa-jwt", "123456").
					Return(nil, errors.New("db error"))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, c := newTestHandler(t)
			tt.mockSetup(c)

			rec := doRequest(h.VerifyTOTP, http.MethodPost, "/api/v1/mfa/verify", tt.body, "")

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestVerifyRecovery(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(c *mocks.Completer)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"mfa_token":"mfa-jwt","code":"AAAA-BBBB"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFARecovery(mock.Anything, "mfa-jwt", "AAAA-BBBB").
					Return(&model.TokenPair{
						AccessToken:  "access-tok",
						RefreshToken: "refresh-tok",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"access-tok","refresh_token":"refresh-tok","expires_in":900,"token_type":"Bearer"}`,
		},
		{
			name:       "invalid json",
			body:       "not-json",
			mockSetup:  func(c *mocks.Completer) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "recovery code not found",
			body: `{"mfa_token":"mfa-jwt","code":"BAD-CODE"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFARecovery(mock.Anything, "mfa-jwt", "BAD-CODE").
					Return(nil, domainerrors.ErrRecoveryCodeNotFound)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid recovery code","code":"INVALID_RECOVERY_CODE"}`,
		},
		{
			name: "invalid mfa token",
			body: `{"mfa_token":"expired","code":"AAAA-BBBB"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFARecovery(mock.Anything, "expired", "AAAA-BBBB").
					Return(nil, domainerrors.ErrInvalidMFAToken)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid or expired mfa token","code":"INVALID_MFA_TOKEN"}`,
		},
		{
			name: "mfa not enabled",
			body: `{"mfa_token":"mfa-jwt","code":"AAAA-BBBB"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFARecovery(mock.Anything, "mfa-jwt", "AAAA-BBBB").
					Return(nil, domainerrors.ErrMFANotEnabled)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"mfa not enabled","code":"MFA_NOT_ENABLED"}`,
		},
		{
			name: "internal error",
			body: `{"mfa_token":"mfa-jwt","code":"AAAA-BBBB"}`,
			mockSetup: func(c *mocks.Completer) {
				c.EXPECT().CompleteMFARecovery(mock.Anything, "mfa-jwt", "AAAA-BBBB").
					Return(nil, errors.New("db error"))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, c := newTestHandler(t)
			tt.mockSetup(c)

			rec := doRequest(h.VerifyRecovery, http.MethodPost, "/api/v1/mfa/verify-recovery", tt.body, "")

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}
