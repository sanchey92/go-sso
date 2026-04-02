package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/federation/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/metrics"
)

func withChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Keys = append(rctx.URLParams.Keys, key)
	rctx.URLParams.Values = append(rctx.URLParams.Values, value)

	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	return r.WithContext(ctx)
}

func TestHandler_Authorize(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		setup      func(fi *mocks.Initiator)
		wantStatus int
		wantHeader string
	}{
		{
			name:     "redirect_to_google",
			provider: "google",
			setup: func(fi *mocks.Initiator) {
				fi.EXPECT().InitiateOAuth(mock.Anything, "google").
					Return("https://accounts.google.com/auth?state=abc", nil)
			},
			wantStatus: http.StatusFound,
			wantHeader: "https://accounts.google.com/auth?state=abc",
		},
		{
			name:     "unknown_provider",
			provider: "facebook",
			setup: func(fi *mocks.Initiator) {
				fi.EXPECT().InitiateOAuth(mock.Anything, "facebook").
					Return("", domainerrors.ErrProviderNotSupported)
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator := mocks.NewInitiator(t)
			tt.setup(initiator)

			h := NewHandler(initiator, nil, metrics.NewTest(), zap.NewNop())

			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/"+tt.provider+"/authorize", nil)
			req = withChiParam(req, "provider", tt.provider)

			rec := httptest.NewRecorder()
			h.Authorize(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantHeader != "" {
				assert.Equal(t, tt.wantHeader, rec.Header().Get("Location"))
			}
		})
	}
}

func TestHandler_Callback(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		query      string
		setup      func(cb *mocks.CallbackHandler)
		wantStatus int
		check      func(t *testing.T, body string)
	}{
		{
			name:     "success",
			provider: "google",
			query:    "code=auth-code&state=valid-state",
			setup: func(cb *mocks.CallbackHandler) {
				cb.EXPECT().HandleCallback(mock.Anything, "google", "auth-code", "valid-state").
					Return(&model.TokenPair{
						AccessToken:  "access-tok",
						RefreshToken: "refresh-tok",
						ExpiresIn:    900,
					}, nil)
			},
			wantStatus: http.StatusOK,
			check: func(t *testing.T, body string) {
				var resp tokenResponse
				require.NoError(t, json.Unmarshal([]byte(body), &resp))
				assert.Equal(t, "access-tok", resp.AccessToken)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Equal(t, int64(900), resp.ExpiresIn)
				assert.Equal(t, "refresh-tok", resp.RefreshToken)
			},
		},
		{
			name:       "missing_code",
			provider:   "google",
			query:      "state=valid-state",
			setup:      func(cb *mocks.CallbackHandler) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing_state",
			provider:   "google",
			query:      "code=auth-code",
			setup:      func(cb *mocks.CallbackHandler) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "invalid_state",
			provider: "google",
			query:    "code=auth-code&state=bad",
			setup: func(cb *mocks.CallbackHandler) {
				cb.EXPECT().HandleCallback(mock.Anything, "google", "auth-code", "bad").
					Return(nil, domainerrors.ErrInvalidOAuthState)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "email_not_verified",
			provider: "google",
			query:    "code=auth-code&state=valid",
			setup: func(cb *mocks.CallbackHandler) {
				cb.EXPECT().HandleCallback(mock.Anything, "google", "auth-code", "valid").
					Return(nil, domainerrors.ErrProviderEmailNotVerified)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "provider_error_in_query",
			provider:   "google",
			query:      "error=access_denied&error_description=user+denied+access",
			setup:      func(cb *mocks.CallbackHandler) {},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := mocks.NewCallbackHandler(t)
			tt.setup(callback)

			h := NewHandler(nil, callback, metrics.NewTest(), zap.NewNop())

			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/auth/"+tt.provider+"/callback?"+tt.query, nil)
			req = withChiParam(req, "provider", tt.provider)

			rec := httptest.NewRecorder()
			h.Callback(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.check != nil {
				tt.check(t, rec.Body.String())
			}
		})
	}
}
