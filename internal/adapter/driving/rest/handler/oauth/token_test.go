package oauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func doTokenRequest(handler http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	body := form.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func doTokenRequestWithBasicAuth(handler http.HandlerFunc, form url.Values, user, pass string) *httptest.ResponseRecorder {
	body := form.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, pass)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "empty grant_type",
			form: url.Values{},
		},
		{
			name: "unknown grant_type",
			form: url.Values{"grant_type": {"implicit"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _ := newTestHandler(t)
			rec := doTokenRequest(h.Token, tt.form)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "unsupported_grant_type")
		})
	}
}

func TestToken_AuthorizationCodeGrant(t *testing.T) {
	validForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"auth-code-123"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"client_id":     {"client-123"},
		"client_secret": {"secret-456"},
	}

	tests := []struct {
		name      string
		form      url.Values
		basicAuth *[2]string // {user, pass} — если != nil, используем Basic Auth
		setupMock func(ex *mocks.Exchanger)
		wantCode  int
		checkBody func(t *testing.T, body string)
	}{
		{
			name: "successful exchange",
			form: validForm,
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.AnythingOfType("*model.CodeExchangeRequest")).
					Return(&model.TokenPair{
						AccessToken:  "access-token-xyz",
						RefreshToken: "refresh-token-xyz",
						ExpiresIn:    3600,
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "access-token-xyz")
				assert.Contains(t, body, "refresh-token-xyz")
				assert.Contains(t, body, `"token_type":"Bearer"`)
				assert.Contains(t, body, `"expires_in":3600`)
			},
		},
		{
			name: "successful exchange with Basic Auth",
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"auth-code-123"},
				"redirect_uri":  {"https://app.example.com/callback"},
				"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
			},
			basicAuth: &[2]string{"client-123", "secret-456"},
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.MatchedBy(func(req *model.CodeExchangeRequest) bool {
						return req.ClientID == "client-123" && req.ClientSecret == "secret-456"
					})).
					Return(&model.TokenPair{
						AccessToken:  "access-token-basic",
						RefreshToken: "refresh-token-basic",
						ExpiresIn:    3600,
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "access-token-basic")
			},
		},
		{
			name: "missing code",
			form: func() url.Values {
				f := copyParams(validForm)
				f.Del("code")
				return f
			}(),
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "code is required")
			},
		},
		{
			name: "missing redirect_uri",
			form: func() url.Values {
				f := copyParams(validForm)
				f.Del("redirect_uri")
				return f
			}(),
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "redirect_uri is required")
			},
		},
		{
			name: "missing code_verifier",
			form: func() url.Values {
				f := copyParams(validForm)
				f.Del("code_verifier")
				return f
			}(),
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "code verifier is required")
			},
		},
		{
			name: "missing client_id",
			form: func() url.Values {
				f := copyParams(validForm)
				f.Del("client_id")
				f.Del("client_secret")
				return f
			}(),
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "client_id is required")
			},
		},
		{
			name: "invalid authorization code",
			form: validForm,
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.Anything).
					Return(nil, domainerrors.ErrInvalidAuthorizationCode)
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_grant")
			},
		},
		{
			name: "invalid client credentials",
			form: validForm,
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.Anything).
					Return(nil, domainerrors.ErrInvalidCredentials)
			},
			wantCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_client")
			},
		},
		{
			name: "client not found",
			form: validForm,
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.Anything).
					Return(nil, domainerrors.ErrOAuthClientNotFound)
			},
			wantCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_client")
			},
		},
		{
			name: "internal server error",
			form: validForm,
			setupMock: func(ex *mocks.Exchanger) {
				ex.EXPECT().
					ExchangeCode(mock.Anything, mock.Anything).
					Return(nil, errors.New("database connection lost"))
			},
			wantCode: http.StatusInternalServerError,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "server_error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, exMock, _ := newTestHandler(t)
			if tt.setupMock != nil {
				tt.setupMock(exMock)
			}

			var rec *httptest.ResponseRecorder
			if tt.basicAuth != nil {
				rec = doTokenRequestWithBasicAuth(h.Token, tt.form, tt.basicAuth[0], tt.basicAuth[1])
			} else {
				rec = doTokenRequest(h.Token, tt.form)
			}

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.String())
			}

			// RFC 6749 §5.1: Cache-Control headers
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		})
	}
}

func TestToken_RefreshTokenGrant(t *testing.T) {
	tests := []struct {
		name      string
		form      url.Values
		setupMock func(ref *mocks.Refresher)
		wantCode  int
		checkBody func(t *testing.T, body string)
	}{
		{
			name: "successful refresh",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"old-refresh-token"},
			},
			setupMock: func(ref *mocks.Refresher) {
				ref.EXPECT().
					RefreshTokens(mock.Anything, "old-refresh-token").
					Return(&model.TokenPair{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						ExpiresIn:    3600,
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "new-access-token")
				assert.Contains(t, body, "new-refresh-token")
				assert.Contains(t, body, `"token_type":"Bearer"`)
			},
		},
		{
			name: "missing refresh_token",
			form: url.Values{
				"grant_type": {"refresh_token"},
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "refresh_token is required")
			},
		},
		{
			name: "expired refresh token",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"expired-token"},
			},
			setupMock: func(ref *mocks.Refresher) {
				ref.EXPECT().
					RefreshTokens(mock.Anything, "expired-token").
					Return(nil, domainerrors.ErrTokenExpired)
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_grant")
				assert.Contains(t, body, "expired")
			},
		},
		{
			name: "revoked refresh token",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"revoked-token"},
			},
			setupMock: func(ref *mocks.Refresher) {
				ref.EXPECT().
					RefreshTokens(mock.Anything, "revoked-token").
					Return(nil, domainerrors.ErrTokenRevoked)
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_grant")
				assert.Contains(t, body, "revoked")
			},
		},
		{
			name: "invalid refresh token",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"invalid-token"},
			},
			setupMock: func(ref *mocks.Refresher) {
				ref.EXPECT().
					RefreshTokens(mock.Anything, "invalid-token").
					Return(nil, domainerrors.ErrInvalidToken)
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_grant")
			},
		},
		{
			name: "internal server error",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"some-token"},
			},
			setupMock: func(ref *mocks.Refresher) {
				ref.EXPECT().
					RefreshTokens(mock.Anything, "some-token").
					Return(nil, errors.New("redis timeout"))
			},
			wantCode: http.StatusInternalServerError,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "server_error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, refMock := newTestHandler(t)
			if tt.setupMock != nil {
				tt.setupMock(refMock)
			}

			rec := doTokenRequest(h.Token, tt.form)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.String())
			}

			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		})
	}
}
