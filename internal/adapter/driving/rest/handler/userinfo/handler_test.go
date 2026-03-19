package userinfo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/userinfo/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func newTestHandler(t *testing.T) (*Handler, *mocks.InfoProvider) {
	t.Helper()
	svc := mocks.NewInfoProvider(t)
	h := NewHandler(svc, zap.NewNop())
	return h, svc
}

func doUserInfoRequest(handler http.HandlerFunc, bearerToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/userinfo", nil)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestUserInfo(t *testing.T) {
	tests := []struct {
		name         string
		bearerToken  string
		setupMock    func(svc *mocks.InfoProvider)
		wantCode     int
		checkWWWAuth func(t *testing.T, header string)
		checkBody    func(t *testing.T, body string)
	}{
		{
			name:        "success",
			bearerToken: "valid-token",
			setupMock: func(svc *mocks.InfoProvider) {
				svc.EXPECT().
					GetUserInfo(mock.Anything, "valid-token").
					Return(&model.UserInfo{
						Sub:           "user-123",
						Email:         "user@example.com",
						EmailVerified: true,
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, `"sub":"user-123"`)
				assert.Contains(t, body, `"email":"user@example.com"`)
				assert.Contains(t, body, `"email_verified":true`)
			},
		},
		{
			name:        "no authorization header — 401 with realm only",
			bearerToken: "",
			wantCode:    http.StatusUnauthorized,
			checkWWWAuth: func(t *testing.T, header string) {
				assert.Equal(t, `Bearer realm="sso"`, header)
			},
		},
		{
			name:        "expired token — 401 with invalid_token",
			bearerToken: "expired-token",
			setupMock: func(svc *mocks.InfoProvider) {
				svc.EXPECT().
					GetUserInfo(mock.Anything, "expired-token").
					Return(nil, fmt.Errorf("validate token: %w", domainerrors.ErrTokenExpired))
			},
			wantCode: http.StatusUnauthorized,
			checkWWWAuth: func(t *testing.T, header string) {
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, "expired")
			},
		},
		{
			name:        "invalid token — 401 with invalid_token",
			bearerToken: "garbage-token",
			setupMock: func(svc *mocks.InfoProvider) {
				svc.EXPECT().
					GetUserInfo(mock.Anything, "garbage-token").
					Return(nil, fmt.Errorf("validate token: %w", domainerrors.ErrInvalidToken))
			},
			wantCode: http.StatusUnauthorized,
			checkWWWAuth: func(t *testing.T, header string) {
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, "invalid")
			},
		},
		{
			name:        "user not found — 401",
			bearerToken: "valid-token-deleted-user",
			setupMock: func(svc *mocks.InfoProvider) {
				svc.EXPECT().
					GetUserInfo(mock.Anything, "valid-token-deleted-user").
					Return(nil, fmt.Errorf("get user: %w", domainerrors.ErrUserNotFound))
			},
			wantCode: http.StatusUnauthorized,
			checkWWWAuth: func(t *testing.T, header string) {
				assert.Contains(t, header, `error="invalid_token"`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, svc := newTestHandler(t)
			if tt.setupMock != nil {
				tt.setupMock(svc)
			}

			rec := doUserInfoRequest(h.UserInfo, tt.bearerToken)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.checkWWWAuth != nil {
				tt.checkWWWAuth(t, rec.Header().Get("WWW-Authenticate"))
			}
			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.String())
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
	}{
		{"valid bearer", "Bearer abc123", "abc123"},
		{"empty header", "", ""},
		{"lowercase bearer (invalid per RFC)", "bearer abc123", ""},
		{"no space after Bearer", "Bearerabc123", ""},
		{"Basic auth (not Bearer)", "Basic dXNlcjpwYXNz", ""},
		{"Bearer with JWT", "Bearer eyJhbGciOiJFZERTQSJ9.payload.sig", "eyJhbGciOiJFZERTQSJ9.payload.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			got := extractBearerToken(req)
			assert.Equal(t, tt.want, got)
		})
	}
}
