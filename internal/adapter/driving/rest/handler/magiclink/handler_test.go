package magiclink

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/magiclink/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/metrics"
)

func doRequest(handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func newTestHandler(t *testing.T) (*Handler, *mocks.LinkRequester, *mocks.LinkVerifier) {
	t.Helper()
	lr := mocks.NewLinkRequester(t)
	lv := mocks.NewLinkVerifier(t)
	h := NewHandler(lr, lv, metrics.NewTest(), zap.NewNop())
	return h, lr, lv
}

func TestRequest(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(*mocks.LinkRequester)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"email":"user@example.com"}`,
			mockSetup: func(lr *mocks.LinkRequester) {
				lr.EXPECT().RequestMagicLink(mock.Anything, "user@example.com").Return(nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"message":"if the email exists, a magic link has been sent"}`,
		},
		{
			name:       "invalid json",
			body:       `not json`,
			mockSetup:  func(_ *mocks.LinkRequester) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "internal error",
			body: `{"email":"user@example.com"}`,
			mockSetup: func(lr *mocks.LinkRequester) {
				lr.EXPECT().RequestMagicLink(mock.Anything, "user@example.com").
					Return(fmt.Errorf("cache: %w", errors.New("redis down")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, lr, _ := newTestHandler(t)
			tt.mockSetup(lr)
			rec := doRequest(h.Request, http.MethodPost, "/api/v1/auth/magic-link/request", tt.body)
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(*mocks.LinkVerifier)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"token":"valid-token"}`,
			mockSetup: func(lv *mocks.LinkVerifier) {
				lv.EXPECT().VerifyMagicLink(mock.Anything, "valid-token").
					Return(&model.TokenPair{
						AccessToken:  "at",
						RefreshToken: "rt",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"at","refresh_token":"rt","expires_in":900,"token_type":"Bearer"}`,
		},
		{
			name: "invalid token",
			body: `{"token":"bad-token"}`,
			mockSetup: func(lv *mocks.LinkVerifier) {
				lv.EXPECT().VerifyMagicLink(mock.Anything, "bad-token").
					Return(nil, domainerrors.ErrMagicLinkNotFound)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"invalid or expired magic link","code":"INVALID_MAGIC_LINK"}`,
		},
		{
			name:       "invalid json",
			body:       `{`,
			mockSetup:  func(_ *mocks.LinkVerifier) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, lv := newTestHandler(t)
			tt.mockSetup(lv)
			rec := doRequest(h.Verify, http.MethodPost, "/api/v1/auth/magic-link/verify", tt.body)
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}
