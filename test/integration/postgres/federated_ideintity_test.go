//go:build integration

package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func TestLinkIdentityTx_AutoProvision(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	pu := &model.ProviderUser{
		ProviderUserID: "google-auto-123",
		Email:          "auto@example.com",
		EmailVerified:  true,
		Name:           "Auto User",
		AvatarURL:      "https://example.com/avatar.jpg",
	}

	user, created, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)
	assert.True(t, created)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "auto@example.com", user.Email)
	assert.Equal(t, model.UserStatusActive, user.Status)
	assert.True(t, user.EmailVerified)
	assert.Empty(t, user.PasswordHash)

	// Проверяем что FI создана
	fi, err := testStorage.GetByProviderAndProviderUserID(ctx, "google", "google-auto-123")
	require.NoError(t, err)
	assert.Equal(t, user.ID, fi.UserID)
	assert.Equal(t, "Auto User", fi.Name)
}

func TestLinkIdentityTx_RepeatLogin(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	pu := &model.ProviderUser{
		ProviderUserID: "google-repeat-456",
		Email:          "repeat@example.com",
		EmailVerified:  true,
		Name:           "Repeat User",
	}

	user1, created1, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)
	assert.True(t, created1)

	user2, created2, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)
	assert.False(t, created2)
	assert.Equal(t, user1.ID, user2.ID)
}

func TestLinkIdentityTx_AccountLinking(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	existingUser := &model.User{
		Email:         "linked@example.com",
		PasswordHash:  "$argon2id$hash",
		EmailVerified: true,
		Status:        model.UserStatusActive,
	}
	require.NoError(t, testStorage.Create(ctx, existingUser))

	pu := &model.ProviderUser{
		ProviderUserID: "google-link-789",
		Email:          "linked@example.com",
		EmailVerified:  true,
		Name:           "Linked User",
	}

	user, created, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, existingUser.ID, user.ID)

	fi, err := testStorage.GetByProviderAndProviderUserID(ctx, "google", "google-link-789")
	require.NoError(t, err)
	assert.Equal(t, existingUser.ID, fi.UserID)
}

func TestLinkIdentityTx_TwoProvidersSameEmail(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	puGoogle := &model.ProviderUser{
		ProviderUserID: "google-multi-1",
		Email:          "multi@example.com",
		EmailVerified:  true,
	}
	user1, created1, err := testStorage.LinkIdentityTx(ctx, "google", puGoogle)
	require.NoError(t, err)
	assert.True(t, created1)

	puGitHub := &model.ProviderUser{
		ProviderUserID: "github-multi-2",
		Email:          "multi@example.com",
		EmailVerified:  true,
	}
	user2, created2, err := testStorage.LinkIdentityTx(ctx, "github", puGitHub)
	require.NoError(t, err)
	assert.False(t, created2)
	assert.Equal(t, user1.ID, user2.ID)

	fis, err := testStorage.GetByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Len(t, fis, 2)
}

func TestFederatedIdentity_GetByProviderNotFound(t *testing.T) {
	restoreDB(t)

	_, err := testStorage.GetByProviderAndProviderUserID(t.Context(), "github", "nonexistent")
	require.ErrorIs(t, err, domainerrors.ErrFederatedIdentityNotFound)
}

func TestFederatedIdentity_GetByUserID(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	pu := &model.ProviderUser{
		ProviderUserID: "google-getby-1",
		Email:          "getby@example.com",
		EmailVerified:  true,
	}

	user, _, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)

	result, err := testStorage.GetByUserID(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "google", result[0].Provider)
}

func TestFederatedIdentity_CascadeDelete(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	pu := &model.ProviderUser{
		ProviderUserID: "google-cascade-1",
		Email:          "cascade@example.com",
		EmailVerified:  true,
	}

	user, _, err := testStorage.LinkIdentityTx(ctx, "google", pu)
	require.NoError(t, err)

	_, err = testStorage.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, err)

	_, err = testStorage.GetByProviderAndProviderUserID(ctx, "google", "google-cascade-1")
	require.ErrorIs(t, err, domainerrors.ErrFederatedIdentityNotFound)
}
