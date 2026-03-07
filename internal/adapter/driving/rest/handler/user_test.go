package handler

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func newUserHandler(t *testing.T) (*UserHandler, *mocks.UserService) {
	t.Helper()
	us := mocks.NewUserService(t)
	h := NewUserHandler(us, zap.NewNop())
	return h, us
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.UserService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "test@example.com", "secret123").
					Return(&model.User{ID: "user-123"}, nil)
			},
			wantStatus: http.StatusCreated,
			wantBody:   `{"user_id":"user-123","message":"user registered successfully"}`,
		},
		{
			name:       "invalid json",
			body:       `{invalid`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name: "email already exists",
			body: `{"email":"dup@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "dup@example.com", "secret123").
					Return(nil, domainerrors.ErrEmailAlreadyExists)
			},
			wantStatus: http.StatusConflict,
			wantBody:   `{"error":"email already exists","code":"EMAIL_EXISTS"}`,
		},
		{
			name: "validation error",
			body: `{"email":"bad","password":"short"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "bad", "short").
					Return(nil, fmt.Errorf("email: invalid format"))
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"email: invalid format","code":"VALIDATION_ERROR"}`,
		},
		{
			name: "internal error",
			body: `{"email":"test@example.com","password":"secret123"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().Register(mock.Anything, "test@example.com", "secret123").
					Return(nil, fmt.Errorf("hash password: %w", fmt.Errorf("something broke")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, us := newUserHandler(t)
			tt.mockSetup(us)

			rec := doRequest(h.Register, http.MethodPost, "/api/v1/auth/register", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestVerifyEmail(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mockSetup  func(svc *mocks.UserService)
		wantStatus int
		wantBody   string
	}{
		{
			name: "success",
			body: `{"token":"valid-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "valid-token").Return(nil)
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"message":"email verified successfully"}`,
		},
		{
			name:       "invalid json",
			body:       `{bad`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body","code":"INVALID_REQUEST"}`,
		},
		{
			name:       "empty token",
			body:       `{"token":""}`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"token is required","code":"VALIDATION_ERROR"}`,
		},
		{
			name:       "missing token field",
			body:       `{}`,
			mockSetup:  func(_ *mocks.UserService) {},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"token is required","code":"VALIDATION_ERROR"}`,
		},
		{
			name: "invalid verification token",
			body: `{"token":"expired-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "expired-token").
					Return(domainerrors.ErrInvalidVerificationToken)
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid or expired verification token","code":"INVALID_VERIFICATION_TOKEN"}`,
		},
		{
			name: "internal error",
			body: `{"token":"some-token"}`,
			mockSetup: func(svc *mocks.UserService) {
				svc.EXPECT().VerifyEmail(mock.Anything, "some-token").
					Return(fmt.Errorf("update email verified: %w", fmt.Errorf("db error")))
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error","code":"INTERNAL_ERROR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, us := newUserHandler(t)
			tt.mockSetup(us)

			rec := doRequest(h.VerifyEmail, http.MethodPost, "/api/v1/auth/email/verify", tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}
