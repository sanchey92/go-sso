package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func newOAuthHandler(t *testing.T) (*OAuthHandler, *mocks.OAuthAuthorizeService) {
	t.Helper()
	svc := mocks.NewOAuthAuthorizeService(t)
	h := NewOAuthHandler(svc, zap.NewNop())
	return h, svc
}

func doAuthorizeRequest(handler http.HandlerFunc, params url.Values) *httptest.ResponseRecorder {
	target := "/api/v1/oauth/authorize?" + params.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestOAuthHandler_Authorize(t *testing.T) {
	validParams := url.Values{
		"client_id":             {"client-123"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {"random-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"user_id":               {"user-456"},
	}

	tests := []struct {
		name          string
		params        url.Values
		setupMock     func(svc *mocks.OAuthAuthorizeService)
		wantStatus    int
		wantRedirect  bool
		checkRedirect func(t *testing.T, location string)
		checkBody     func(t *testing.T, body string)
	}{
		{
			name:   "successful authorize — redirects with code and state",
			params: validParams,
			setupMock: func(svc *mocks.OAuthAuthorizeService) {
				svc.EXPECT().
					Authorize(mock.Anything, mock.AnythingOfType("*model.AuthorizationCode")).
					Return("test-auth-code", nil)
			},
			wantStatus:   http.StatusFound,
			wantRedirect: true,
			checkRedirect: func(t *testing.T, location string) {
				u, err := url.Parse(location)
				require.NoError(t, err)
				assert.Equal(t, "test-auth-code", u.Query().Get("code"))
				assert.Equal(t, "random-state", u.Query().Get("state"))
				assert.Equal(t, "app.example.com", u.Host)
			},
		},
		{
			name: "missing client_id — direct error response",
			params: func() url.Values {
				p := copyParams(validParams)
				p.Del("client_id")
				return p
			}(),
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "INVALID_REQUEST")
			},
		},
		{
			name: "missing redirect_uri — direct error response",
			params: func() url.Values {
				p := copyParams(validParams)
				p.Del("redirect_uri")
				return p
			}(),
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "INVALID_REQUEST")
			},
		},
		{
			name: "wrong response_type — redirect with error",
			params: func() url.Values {
				p := copyParams(validParams)
				p.Set("response_type", "token")
				return p
			}(),
			wantStatus:   http.StatusFound,
			wantRedirect: true,
			checkRedirect: func(t *testing.T, location string) {
				u, _ := url.Parse(location)
				assert.Equal(t, "unsupported_response_type", u.Query().Get("error"))
				assert.Equal(t, "random-state", u.Query().Get("state"))
			},
		},
		{
			name: "missing code_challenge — redirect with error",
			params: func() url.Values {
				p := copyParams(validParams)
				p.Del("code_challenge")
				return p
			}(),
			wantStatus:   http.StatusFound,
			wantRedirect: true,
			checkRedirect: func(t *testing.T, location string) {
				u, _ := url.Parse(location)
				assert.Equal(t, "invalid_request", u.Query().Get("error"))
			},
		},
		{
			name: "wrong code_challenge_method — redirect with error",
			params: func() url.Values {
				p := copyParams(validParams)
				p.Set("code_challenge_method", "plain")
				return p
			}(),
			wantStatus:   http.StatusFound,
			wantRedirect: true,
			checkRedirect: func(t *testing.T, location string) {
				u, _ := url.Parse(location)
				assert.Equal(t, "invalid_request", u.Query().Get("error"))
			},
		},
		{
			name:   "invalid client_id — direct error (no redirect per RFC)",
			params: validParams,
			setupMock: func(svc *mocks.OAuthAuthorizeService) {
				svc.EXPECT().
					Authorize(mock.Anything, mock.Anything).
					Return("", fmt.Errorf("get client: %w", domainerrors.ErrOAuthClientNotFound))
			},
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "INVALID_CLIENT")
			},
		},
		{
			name:   "invalid redirect_uri — direct error (no redirect per RFC)",
			params: validParams,
			setupMock: func(svc *mocks.OAuthAuthorizeService) {
				svc.EXPECT().
					Authorize(mock.Anything, mock.Anything).
					Return("", domainerrors.ErrInvalidRedirectURI)
			},
			wantStatus: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "INVALID_REDIRECT_URI")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, svc := newOAuthHandler(t)
			if tt.setupMock != nil {
				tt.setupMock(svc)
			}

			rec := doAuthorizeRequest(h.Authorize, tt.params)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantRedirect {
				location := rec.Header().Get("Location")
				require.NotEmpty(t, location, "expected Location header for redirect")
				if tt.checkRedirect != nil {
					tt.checkRedirect(t, location)
				}
			}
			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.String())
			}
		})
	}
}

func copyParams(src url.Values) url.Values {
	dst := make(url.Values)
	for k, v := range src {
		dst[k] = append([]string{}, v...)
	}
	return dst
}
