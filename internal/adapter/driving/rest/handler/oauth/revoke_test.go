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
)

func doRevokeRequest(handler http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	body := form.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRevoke(t *testing.T) {
	tests := []struct {
		name      string
		form      url.Values
		setupMock func(rev *mocks.Revoker)
		wantCode  int
		checkBody func(t *testing.T, body string)
	}{
		{
			name: "successful revocation — returns 200",
			form: url.Values{"token": {"valid-refresh-token"}},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "valid-refresh-token").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "invalid token — still returns 200 (RFC 7009)",
			form: url.Values{"token": {"unknown-token"}},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "unknown-token").
					Return(errors.New("get refresh token: invalid token"))
			},
			wantCode: http.StatusOK,
		},
		{
			name: "already revoked token — still returns 200",
			form: url.Values{"token": {"revoked-token"}},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "revoked-token").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "database error — still returns 200 (logged internally)",
			form: url.Values{"token": {"some-token"}},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "some-token").
					Return(errors.New("connection refused"))
			},
			wantCode: http.StatusOK,
		},
		{
			name:     "missing token parameter — returns 400",
			form:     url.Values{},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid_request")
				assert.Contains(t, body, "token is required")
			},
		},
		{
			name: "with token_type_hint — accepted and ignored",
			form: url.Values{
				"token":           {"valid-token"},
				"token_type_hint": {"refresh_token"},
			},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "valid-token").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "with wrong token_type_hint — still works (RFC 7009: MAY ignore hint)",
			form: url.Values{
				"token":           {"valid-token"},
				"token_type_hint": {"access_token"},
			},
			setupMock: func(rev *mocks.Revoker) {
				rev.EXPECT().
					RevokeToken(mock.Anything, "valid-token").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _, revMock := newTestHandler(t)
			if tt.setupMock != nil {
				tt.setupMock(revMock)
			}

			rec := doRevokeRequest(h.Revoke, tt.form)

			assert.Equal(t, tt.wantCode, rec.Code)

			// RFC 7009: Cache-Control headers
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

			if tt.checkBody != nil {
				tt.checkBody(t, rec.Body.String())
			}
		})
	}
}
