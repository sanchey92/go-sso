package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/app/auth/mocks"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func TestService_Register(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func(h *mocks.Hasher, ur *mocks.UserRepository)
		wantErr   string
		check     func(t *testing.T, user *model.User)
	}{
		{
			name:     "successful registration",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Run(func(_ context.Context, u *model.User) {
						u.ID = "generated-uuid"
					}).
					Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "generated-uuid", user.ID)
				assert.Equal(t, "user@example.com", user.Email)
				assert.Equal(t, "hashed_password", user.PasswordHash)
				assert.Equal(t, model.UserStatusActive, user.Status)
				assert.False(t, user.EmailVerified)
				assert.False(t, user.MFAEnabled)
			},
		},
		{
			name:     "email normalized to lowercase and trimmed",
			email:    "  User@Example.COM  ",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u *model.User) bool {
					return u.Email == "user@example.com"
				})).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "empty email",
			email:     "",
			password:  "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "email: cannot be empty",
		},
		{
			name:      "invalid email format",
			email:     "not-an-email",
			password:  "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "email: invalid format",
		},
		{
			name:      "password too short",
			email:     "user@example.com",
			password:  "short",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:      "empty password",
			email:     "user@example.com",
			password:  "",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
		{
			name:     "hasher returns error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("", errors.New("hash failed"))
			},
			wantErr: "hash password: hash failed",
		},
		{
			name:     "email already exists",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Return(domainerrors.ErrEmailAlreadyExists)
			},
			wantErr: domainerrors.ErrEmailAlreadyExists.Error(),
		},
		{
			name:     "repository returns unexpected error",
			email:    "user@example.com",
			password: "securepassword",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("securepassword").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).
					Return(errors.New("db connection lost"))
			},
			wantErr: "create user: db connection lost",
		},
		{
			name:     "password exactly 8 characters is valid",
			email:    "user@example.com",
			password: "12345678",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {
				h.EXPECT().Hash("12345678").Return("hashed_password", nil)
				ur.EXPECT().Create(mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
			},
			check: func(t *testing.T, user *model.User) {
				assert.Equal(t, "user@example.com", user.Email)
			},
		},
		{
			name:      "password 7 characters is invalid",
			email:     "user@example.com",
			password:  "1234567",
			setupMock: func(h *mocks.Hasher, ur *mocks.UserRepository) {},
			wantErr:   "password: must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := mocks.NewHasher(t)
			userRepo := mocks.NewUserRepository(t)
			tt.setupMock(hasher, userRepo)

			svc := New(hasher, userRepo, zap.NewNop())

			user, err := svc.Register(ctx, tt.email, tt.password)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, user)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, user)

			if tt.check != nil {
				tt.check(t, user)
			}
		})
	}
}
