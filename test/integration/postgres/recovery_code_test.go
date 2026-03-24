//go:build integration

package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/pkg/crypto"
)

func TestStorage_SaveCodes(t *testing.T) {
	t.Run("save and get unused", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "mfa@example.com")

		hashes := []string{
			crypto.HashToken("code-1"),
			crypto.HashToken("code-2"),
			crypto.HashToken("code-3"),
		}

		err := testStorage.SaveCodes(ctx, user.ID, hashes)
		require.NoError(t, err)

		codes, err := testStorage.GetUnusedByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, codes, 3)

		for i, code := range codes {
			assert.Equal(t, user.ID, code.UserID)
			assert.Equal(t, hashes[i], code.CodeHash)
			assert.False(t, code.Used)
			assert.NotEmpty(t, code.ID)
			assert.False(t, code.CreatedAt.IsZero())
		}
	})

	t.Run("empty hashes", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "empty@example.com")

		err := testStorage.SaveCodes(ctx, user.ID, []string{})
		require.NoError(t, err)

		codes, err := testStorage.GetUnusedByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Empty(t, codes)
	})
}

func TestStorage_MarkUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "mark@example.com")

		hashes := []string{
			crypto.HashToken("mark-1"),
			crypto.HashToken("mark-2"),
		}
		require.NoError(t, testStorage.SaveCodes(ctx, user.ID, hashes))

		codes, err := testStorage.GetUnusedByUserID(ctx, user.ID)
		require.NoError(t, err)
		require.Len(t, codes, 2)

		// Используем первый код
		err = testStorage.MarkUsed(ctx, codes[0].ID)
		require.NoError(t, err)

		// Теперь unused = 1
		unused, err := testStorage.GetUnusedByUserID(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, unused, 1)
		assert.Equal(t, codes[1].ID, unused[0].ID)
	})

	t.Run("not found", func(t *testing.T) {
		restoreDB(t)

		err := testStorage.MarkUsed(t.Context(), "00000000-0000-0000-0000-000000000000")
		require.ErrorIs(t, err, domainerrors.ErrRecoveryCodeNotFound)
	})
}

func TestStorage_DeleteByUserID_RecoveryCodes(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	user := createTestUser(t, ctx, "delete@example.com")

	hashes := []string{crypto.HashToken("del-1"), crypto.HashToken("del-2")}
	require.NoError(t, testStorage.SaveCodes(ctx, user.ID, hashes))

	err := testStorage.DeleteByUserID(ctx, user.ID)
	require.NoError(t, err)

	codes, err := testStorage.GetUnusedByUserID(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, codes)
}

func TestStorage_UpdateMFA(t *testing.T) {
	t.Run("enable mfa", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "mfa-update@example.com")

		secretEnc := []byte("encrypted-totp-secret")
		err := testStorage.UpdateMFA(ctx, user.ID, true, secretEnc)
		require.NoError(t, err)

		got, err := testStorage.GetByEmail(ctx, "mfa-update@example.com")
		require.NoError(t, err)
		assert.True(t, got.MFAEnabled)
		assert.Equal(t, secretEnc, got.MFASecretEnc)
		assert.True(t, got.UpdatedAt.After(user.UpdatedAt) || got.UpdatedAt.Equal(user.UpdatedAt))
	})

	t.Run("disable mfa", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "mfa-disable@example.com")

		// Сначала включаем
		require.NoError(t, testStorage.UpdateMFA(ctx, user.ID, true, []byte("secret")))

		// Выключаем: mfa_enabled=false, mfa_secret_enc=nil
		err := testStorage.UpdateMFA(ctx, user.ID, false, nil)
		require.NoError(t, err)

		got, err := testStorage.GetByEmail(ctx, "mfa-disable@example.com")
		require.NoError(t, err)
		assert.False(t, got.MFAEnabled)
		assert.Nil(t, got.MFASecretEnc)
	})

	t.Run("user not found", func(t *testing.T) {
		restoreDB(t)

		err := testStorage.UpdateMFA(t.Context(), "00000000-0000-0000-0000-000000000000", true, []byte("secret"))
		require.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})
}

func TestStorage_RecoveryCodes_CascadeDelete(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	// Создаём юзера через raw SQL чтобы потом удалить
	user := createTestUser(t, ctx, "cascade@example.com")

	hashes := []string{crypto.HashToken("cascade-1")}
	require.NoError(t, testStorage.SaveCodes(ctx, user.ID, hashes))

	// Удаляем юзера напрямую через pool
	_, err := testStorage.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID)
	require.NoError(t, err)

	// Recovery codes должны быть удалены каскадно
	codes, err := testStorage.GetUnusedByUserID(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, codes)
}
