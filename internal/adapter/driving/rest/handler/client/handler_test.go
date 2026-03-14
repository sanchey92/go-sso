package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func doRequest(handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func doRequestWithChiParam(handler http.HandlerFunc, method, path, paramName, paramValue, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(paramName, paramValue)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func newTestHandler(t *testing.T) (*Handler, *mocks.OAuthService) {
	t.Helper()
	svc := mocks.NewOAuthService(t)
	h := NewHandler(svc, zap.NewNop())
	return h, svc
}

func TestOAuthClientHandler_Create(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.OAuthService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"name":"My App","redirect_uris":["https://app.example.com/callback"],"allowed_scopes":["openid","profile"],"is_confidential":true}`,
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					Create(mock.Anything, "My App", []string{"https://app.example.com/callback"}, []string{"openid", "profile"}, true).
					Return("client-id-123", "raw-secret-456", nil)
			},
			wantStatus: http.StatusCreated,
			wantBody:   `{"client_id":"client-id-123","client_secret":"raw-secret-456"}`,
		},
		{
			name:       "invalid json",
			body:       `not json`,
			mockSetup:  func(_ *mocks.OAuthService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name:       "empty body",
			body:       ``,
			mockSetup:  func(_ *mocks.OAuthService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "service internal error",
			body: `{"name":"App","redirect_uris":["https://app.example.com/cb"],"allowed_scopes":["openid"],"is_confidential":true}`,
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					Create(mock.Anything, "App", []string{"https://app.example.com/cb"}, []string{"openid"}, true).
					Return("", "", fmt.Errorf("generate client secret: %w", errors.New("crypto/rand failed")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
		{
			name: "public client",
			body: `{"name":"SPA","redirect_uris":["https://spa.example.com/callback"],"allowed_scopes":["openid"],"is_confidential":false}`,
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					Create(mock.Anything, "SPA", []string{"https://spa.example.com/callback"}, []string{"openid"}, false).
					Return("public-client-id", "public-secret", nil)
			},
			wantStatus: http.StatusCreated,
			wantBody:   `{"client_id":"public-client-id","client_secret":"public-secret"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, svc := newTestHandler(t)
			tt.mockSetup(svc)

			rec := doRequest(h.Create, http.MethodPost, "/api/v1/auth/oauth/clients/", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestOAuthClientHandler_GetByID(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		mockSetup  func(svc *mocks.OAuthService)
		wantStatus int
		wantBody   string
	}{
		{
			name:     "success",
			clientID: "client-123",
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					GetByID(mock.Anything, "client-123").
					Return(&model.OAuthClient{
						ID:             "client-123",
						Name:           "My App",
						RedirectURIs:   []string{"https://app.example.com/callback"},
						AllowedScopes:  []string{"openid", "profile"},
						IsConfidential: true,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"client_id":"client-123","name":"My App","redirect_uris":["https://app.example.com/callback"],"allowed_scopes":["openid","profile"],"is_confidential":true}`,
		},
		{
			name:     "not found",
			clientID: "nonexistent",
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					GetByID(mock.Anything, "nonexistent").
					Return(nil, domainerrors.ErrOAuthClientNotFound)
			},
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":"client not found","code":"CLIENT_NOT_FOUND"}`,
		},
		{
			name:     "internal error",
			clientID: "client-123",
			mockSetup: func(svc *mocks.OAuthService) {
				svc.EXPECT().
					GetByID(mock.Anything, "client-123").
					Return(nil, fmt.Errorf("get oauth client: %w", errors.New("db timeout")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, svc := newTestHandler(t)
			tt.mockSetup(svc)

			rec := doRequestWithChiParam(h.GetByID, http.MethodGet, "/api/v1/auth/oauth/clients/"+tt.clientID, "id", tt.clientID, "")

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}
