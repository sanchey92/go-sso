package mfa

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func newTestHandler(t *testing.T) (*Handler, *mocks.TOTPService, *mocks.TokenValidator, *mocks.Completer) {
	t.Helper()
	ts := mocks.NewTOTPService(t)
	tv := mocks.NewTokenValidator(t)
	c := mocks.NewCompleter(t)
	h := New(ts, tv, c, zap.NewNop())
	return h, ts, tv, c
}

func doRequest(handler http.HandlerFunc, method, path, body, bearerToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "valid bearer",
			header: "Bearer abc123",
			want:   "abc123",
		},
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
		{
			name:   "lowercase bearer",
			header: "bearer abc123",
			want:   "",
		},
		{
			name:   "no space after Bearer",
			header: "Bearerabc123",
			want:   "",
		},
		{
			name:   "basic auth",
			header: "Basic dXNlcjpwYXNz",
			want:   "",
		},
		{
			name:   "bearer with JWT",
			header: "Bearer eyJhbGciOiJFZERTQSJ9.payload.sig",
			want:   "eyJhbGciOiJFZERTQSJ9.payload.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got := extractBearerToken(req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetup(t *testing.T) {
	tests := []struct {
		name        string
		bearerToken string
		mockSetup   func(tv *mocks.TokenValidator, ts *mocks.TOTPService)
		wantStatus  int
		wantBody    string
		checkHeader func(t *testing.T, header http.Header)
	}{
		{
			name:        "success",
			bearerToken: "valid-token",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().SetupTOTP(mock.Anything, "user-123").
					Return("otpauth://totp/SSO:user@example.com?secret=ABC", nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"secret_uri":"otpauth://totp/SSO:user@example.com?secret=ABC"}`,
		},
		{
			name:        "missing bearer token",
			bearerToken: "",
			mockSetup:   func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {},
			wantStatus:  http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Equal(t, `Bearer realm="sso"`, header.Get("WWW-Authenticate"))
			},
		},
		{
			name:        "invalid bearer token",
			bearerToken: "bad-token",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("bad-token").Return("", domainerrors.ErrInvalidToken)
			},
			wantStatus: http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Contains(t, header.Get("WWW-Authenticate"), `error="invalid_token"`)
			},
		},
		{
			name:        "mfa already enabled",
			bearerToken: "valid-token",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().SetupTOTP(mock.Anything, "user-123").Return("", domainerrors.ErrMFAAlreadyEnabled)
			},
			wantStatus: http.StatusConflict,
			wantBody:   `{"error":"mfa already enabled","code":"MFA_ALREADY_ENABLED"}`,
		},
		{
			name:        "internal error",
			bearerToken: "valid-token",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().SetupTOTP(mock.Anything, "user-123").Return("", errors.New("db failure"))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ts, tv, _ := newTestHandler(t)
			tt.mockSetup(tv, ts)

			rec := doRequest(h.Setup, http.MethodPost, "/api/v1/mfa/setup", "", tt.bearerToken)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			}
			if tt.checkHeader != nil {
				tt.checkHeader(t, rec.Header())
			}
		})
	}
}

func TestVerifySetup(t *testing.T) {
	tests := []struct {
		name        string
		bearerToken string
		body        string
		mockSetup   func(tv *mocks.TokenValidator, ts *mocks.TOTPService)
		wantStatus  int
		wantBody    string
		checkHeader func(t *testing.T, header http.Header)
	}{
		{
			name:        "success",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().VerifySetup(mock.Anything, "user-123", "123456").
					Return([]string{"AAAA-BBBB", "CCCC-DDDD"}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"recovery_codes":["AAAA-BBBB","CCCC-DDDD"]}`,
		},
		{
			name:        "missing bearer token",
			bearerToken: "",
			body:        `{"code":"123456"}`,
			mockSetup:   func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {},
			wantStatus:  http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Equal(t, `Bearer realm="sso"`, header.Get("WWW-Authenticate"))
			},
		},
		{
			name:        "invalid bearer token",
			bearerToken: "bad-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("bad-token").Return("", domainerrors.ErrInvalidToken)
			},
			wantStatus: http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Contains(t, header.Get("WWW-Authenticate"), `error="invalid_token"`)
			},
		},
		{
			name:        "invalid json body",
			bearerToken: "valid-token",
			body:        "not-json",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name:        "invalid totp code",
			bearerToken: "valid-token",
			body:        `{"code":"wrong"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().VerifySetup(mock.Anything, "user-123", "wrong").
					Return(nil, domainerrors.ErrInvalidTOTPCode)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid totp code","code":"INVALID_TOTP_CODE"}`,
		},
		{
			name:        "mfa not enabled",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().VerifySetup(mock.Anything, "user-123", "123456").
					Return(nil, domainerrors.ErrMFANotEnabled)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"mfa not enabled","code":"MFA_NOT_ENABLED"}`,
		},
		{
			name:        "internal error",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().VerifySetup(mock.Anything, "user-123", "123456").
					Return(nil, errors.New("db error"))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ts, tv, _ := newTestHandler(t)
			tt.mockSetup(tv, ts)

			rec := doRequest(h.VerifySetup, http.MethodPost, "/api/v1/mfa/verify-setup", tt.body, tt.bearerToken)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			}
			if tt.checkHeader != nil {
				tt.checkHeader(t, rec.Header())
			}
		})
	}
}

func TestDisable(t *testing.T) {
	tests := []struct {
		name        string
		bearerToken string
		body        string
		mockSetup   func(tv *mocks.TokenValidator, ts *mocks.TOTPService)
		wantStatus  int
		wantBody    string
		checkHeader func(t *testing.T, header http.Header)
	}{
		{
			name:        "success",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().DisableTOTP(mock.Anything, "user-123", "123456").Return(nil)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:        "missing bearer token",
			bearerToken: "",
			body:        `{"code":"123456"}`,
			mockSetup:   func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {},
			wantStatus:  http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Equal(t, `Bearer realm="sso"`, header.Get("WWW-Authenticate"))
			},
		},
		{
			name:        "invalid bearer token",
			bearerToken: "bad-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("bad-token").Return("", domainerrors.ErrInvalidToken)
			},
			wantStatus: http.StatusUnauthorized,
			checkHeader: func(t *testing.T, header http.Header) {
				t.Helper()
				assert.Contains(t, header.Get("WWW-Authenticate"), `error="invalid_token"`)
			},
		},
		{
			name:        "invalid json body",
			bearerToken: "valid-token",
			body:        "{bad",
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name:        "mfa not enabled",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().DisableTOTP(mock.Anything, "user-123", "123456").
					Return(domainerrors.ErrMFANotEnabled)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"mfa not enabled","code":"MFA_NOT_ENABLED"}`,
		},
		{
			name:        "invalid totp code",
			bearerToken: "valid-token",
			body:        `{"code":"wrong"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().DisableTOTP(mock.Anything, "user-123", "wrong").
					Return(domainerrors.ErrInvalidTOTPCode)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid totp code","code":"INVALID_TOTP_CODE"}`,
		},
		{
			name:        "internal error",
			bearerToken: "valid-token",
			body:        `{"code":"123456"}`,
			mockSetup: func(tv *mocks.TokenValidator, ts *mocks.TOTPService) {
				tv.EXPECT().ValidateToken("valid-token").Return("user-123", nil)
				ts.EXPECT().DisableTOTP(mock.Anything, "user-123", "123456").
					Return(errors.New("db error"))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ts, tv, _ := newTestHandler(t)
			tt.mockSetup(tv, ts)

			rec := doRequest(h.Disable, http.MethodPost, "/api/v1/mfa/disable", tt.body, tt.bearerToken)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			}
			if tt.checkHeader != nil {
				tt.checkHeader(t, rec.Header())
			}
		})
	}
}
