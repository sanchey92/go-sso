//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	pgadapter "github.com/sanchey92/sso/internal/adapter/driven/postgres"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/crypto"
)

func init() {
	// testcontainers postgres module uses "postgres" driver name for snapshot/restore;
	// pgx/v5/stdlib registers as "pgx", so re-register the same driver as "postgres".
	db, err := sql.Open("pgx", "")
	if err == nil {
		sql.Register("postgres", db.Driver())
		db.Close()
	}
}

var (
	testStorage *pgadapter.Storage
	testCtr     *tcpostgres.PostgresContainer
	testConnStr string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("sso_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		panic("failed to start postgres container: " + err.Error())
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic("failed to get connection string: " + err.Error())
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		panic("failed to open sql connection: " + err.Error())
	}

	if err := goose.Up(db, "../../../../migrations"); err != nil {
		panic("failed to run migrations: " + err.Error())
	}
	db.Close()

	if err := ctr.Snapshot(ctx, tcpostgres.WithSnapshotName("clean")); err != nil {
		panic("failed to create snapshot: " + err.Error())
	}

	storage, err := pgadapter.New(ctx, &pgadapter.Config{
		DSN:             connStr,
		MaxConns:        5,
		MinConns:        1,
		MaxConnLifetime: time.Minute,
		MaxConnIdleTime: time.Minute,
	}, zap.NewNop())
	if err != nil {
		panic("failed to create storage: " + err.Error())
	}

	testStorage = storage
	testCtr = ctr
	testConnStr = connStr

	code := m.Run()

	storage.Close()
	_ = ctr.Terminate(ctx)

	os.Exit(code)
}

func restoreDB(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	testStorage.Close()

	err := testCtr.Restore(ctx, tcpostgres.WithSnapshotName("clean"))
	require.NoError(t, err, "failed to restore database snapshot")

	storage, err := pgadapter.New(ctx, &pgadapter.Config{
		DSN:             testConnStr,
		MaxConns:        5,
		MinConns:        1,
		MaxConnLifetime: time.Minute,
		MaxConnIdleTime: time.Minute,
	}, zap.NewNop())
	require.NoError(t, err, "failed to reconnect after restore")

	testStorage = storage
}

func createTestUser(t *testing.T, ctx context.Context, email string) *model.User {
	t.Helper()
	user := model.NewUser(email, "$argon2id$hash")
	err := testStorage.Create(ctx, user)
	require.NoError(t, err)
	return user
}

func mustGenerateUUID(t *testing.T) string {
	t.Helper()
	id, err := crypto.GenerateUUID()
	require.NoError(t, err)
	return id
}

// --- User Repository ---

func TestStorage_CreateUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)

		user := model.NewUser("test@example.com", "$argon2id$hash")
		err := testStorage.Create(t.Context(), user)
		require.NoError(t, err)

		assert.NotEmpty(t, user.ID, "ID should be set by DB")
		assert.False(t, user.CreatedAt.IsZero(), "CreatedAt should be set")
		assert.False(t, user.UpdatedAt.IsZero(), "UpdatedAt should be set")
	})

	t.Run("duplicate email", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		first := model.NewUser("duplicate@example.com", "$argon2id$hash")
		err := testStorage.Create(ctx, first)
		require.NoError(t, err)

		second := model.NewUser("duplicate@example.com", "$argon2id$hash")
		err = testStorage.Create(ctx, second)
		require.ErrorIs(t, err, domainerrors.ErrEmailAlreadyExists)
	})

	t.Run("CHECK constraint rejects uppercase email", func(t *testing.T) {
		restoreDB(t)

		user := model.NewUser("UPPER@EXAMPLE.COM", "$argon2id$hash")
		err := testStorage.Create(t.Context(), user)
		require.Error(t, err)
	})
}

func TestStorage_GetByEmail(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	user := model.NewUser("get@example.com", "$argon2id$hash")
	err := testStorage.Create(ctx, user)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		got, err := testStorage.GetByEmail(ctx, "get@example.com")
		require.NoError(t, err)

		assert.Equal(t, user.ID, got.ID)
		assert.Equal(t, "get@example.com", got.Email)
		assert.Equal(t, "$argon2id$hash", got.PasswordHash)
		assert.False(t, got.EmailVerified)
		assert.False(t, got.MFAEnabled)
		assert.Equal(t, model.UserStatusActive, got.Status)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := testStorage.GetByEmail(ctx, "nobody@example.com")
		require.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})
}

func TestStorage_UpdateEmailVerified(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "verify@example.com")

		err := testStorage.UpdateEmailVerified(ctx, user.ID, true)
		require.NoError(t, err)

		got, err := testStorage.GetByEmail(ctx, "verify@example.com")
		require.NoError(t, err)
		assert.True(t, got.EmailVerified)
		assert.True(t, got.UpdatedAt.After(user.UpdatedAt) || got.UpdatedAt.Equal(user.UpdatedAt))
	})

	t.Run("user not found", func(t *testing.T) {
		restoreDB(t)

		err := testStorage.UpdateEmailVerified(t.Context(), "00000000-0000-0000-0000-000000000000", true)
		require.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})
}

func TestStorage_UpdatePassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "pwd@example.com")

		newHash := "$argon2id$newhash"
		err := testStorage.UpdatePassword(ctx, user.ID, newHash)
		require.NoError(t, err)

		got, err := testStorage.GetByEmail(ctx, "pwd@example.com")
		require.NoError(t, err)
		assert.Equal(t, newHash, got.PasswordHash)
	})

	t.Run("user not found", func(t *testing.T) {
		restoreDB(t)

		err := testStorage.UpdatePassword(t.Context(), "00000000-0000-0000-0000-000000000000", "$argon2id$hash")
		require.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})
}

// --- RefreshToken Repository ---

func TestStorage_SaveToken(t *testing.T) {
	t.Run("success without client_id", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "token@example.com")

		rt := &model.RefreshToken{
			TokenHash: crypto.HashToken("raw-token-1"),
			UserID:    user.ID,
			FamilyID:  mustGenerateUUID(t),
			Scopes:    []string{"openid", "profile"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := testStorage.SaveToken(ctx, rt)
		require.NoError(t, err)

		assert.NotEmpty(t, rt.ID)
		assert.False(t, rt.CreatedAt.IsZero())
	})

	t.Run("duplicate token_hash", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "dup-token@example.com")
		hash := crypto.HashToken("same-raw-token")

		first := &model.RefreshToken{
			TokenHash: hash,
			UserID:    user.ID,
			FamilyID:  mustGenerateUUID(t),
			Scopes:    []string{"openid"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := testStorage.SaveToken(ctx, first)
		require.NoError(t, err)

		second := &model.RefreshToken{
			TokenHash: hash,
			UserID:    user.ID,
			FamilyID:  mustGenerateUUID(t),
			Scopes:    []string{"openid"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err = testStorage.SaveToken(ctx, second)
		require.Error(t, err, "duplicate token_hash should fail")
	})
}

func TestStorage_GetByHash(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	user := createTestUser(t, ctx, "getbyhash@example.com")
	hash := crypto.HashToken("lookup-token")
	familyID := mustGenerateUUID(t)

	rt := &model.RefreshToken{
		TokenHash: hash,
		UserID:    user.ID,
		FamilyID:  familyID,
		Scopes:    []string{"openid", "email"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := testStorage.SaveToken(ctx, rt)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		got, err := testStorage.GetByHash(ctx, hash)
		require.NoError(t, err)

		assert.Equal(t, rt.ID, got.ID)
		assert.Equal(t, hash, got.TokenHash)
		assert.Equal(t, user.ID, got.UserID)
		assert.Empty(t, got.ClientID)
		assert.Equal(t, familyID, got.FamilyID)
		assert.Equal(t, []string{"openid", "email"}, got.Scopes)
		assert.False(t, got.Revoked)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := testStorage.GetByHash(ctx, "nonexistent-hash")
		require.ErrorIs(t, err, domainerrors.ErrInvalidToken)
	})
}

func TestStorage_Revoke(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)
		ctx := t.Context()

		user := createTestUser(t, ctx, "revoke@example.com")
		hash := crypto.HashToken("revoke-token")

		rt := &model.RefreshToken{
			TokenHash: hash,
			UserID:    user.ID,
			FamilyID:  mustGenerateUUID(t),
			Scopes:    []string{"openid"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := testStorage.SaveToken(ctx, rt)
		require.NoError(t, err)

		err = testStorage.Revoke(ctx, rt.ID)
		require.NoError(t, err)

		got, err := testStorage.GetByHash(ctx, hash)
		require.NoError(t, err)
		assert.True(t, got.Revoked)
	})

	t.Run("token not found", func(t *testing.T) {
		restoreDB(t)

		err := testStorage.Revoke(t.Context(), "00000000-0000-0000-0000-000000000000")
		require.ErrorIs(t, err, domainerrors.ErrInvalidToken)
	})
}

func TestStorage_RevokeByFamilyID(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	user := createTestUser(t, ctx, "family@example.com")
	familyID := mustGenerateUUID(t)
	otherFamilyID := mustGenerateUUID(t)

	// Two tokens in the same family.
	for i, raw := range []string{"family-token-1", "family-token-2"} {
		rt := &model.RefreshToken{
			TokenHash: crypto.HashToken(raw),
			UserID:    user.ID,
			FamilyID:  familyID,
			Scopes:    []string{"openid"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := testStorage.SaveToken(ctx, rt)
		require.NoError(t, err, "token %d", i)
	}

	// One token in a different family.
	other := &model.RefreshToken{
		TokenHash: crypto.HashToken("other-family-token"),
		UserID:    user.ID,
		FamilyID:  otherFamilyID,
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := testStorage.SaveToken(ctx, other)
	require.NoError(t, err)

	err = testStorage.RevokeByFamilyID(ctx, familyID)
	require.NoError(t, err)

	// Both tokens in the target family should be revoked.
	got1, err := testStorage.GetByHash(ctx, crypto.HashToken("family-token-1"))
	require.NoError(t, err)
	assert.True(t, got1.Revoked)

	got2, err := testStorage.GetByHash(ctx, crypto.HashToken("family-token-2"))
	require.NoError(t, err)
	assert.True(t, got2.Revoked)

	// Token in the other family should NOT be revoked.
	gotOther, err := testStorage.GetByHash(ctx, crypto.HashToken("other-family-token"))
	require.NoError(t, err)
	assert.False(t, gotOther.Revoked)
}

func TestStorage_RevokeByUserID(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	user1 := createTestUser(t, ctx, "user1@example.com")
	user2 := createTestUser(t, ctx, "user2@example.com")

	// Two tokens for user1.
	for i, raw := range []string{"user1-token-1", "user1-token-2"} {
		rt := &model.RefreshToken{
			TokenHash: crypto.HashToken(raw),
			UserID:    user1.ID,
			FamilyID:  mustGenerateUUID(t),
			Scopes:    []string{"openid"},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := testStorage.SaveToken(ctx, rt)
		require.NoError(t, err, "user1 token %d", i)
	}

	// One token for user2.
	rt2 := &model.RefreshToken{
		TokenHash: crypto.HashToken("user2-token"),
		UserID:    user2.ID,
		FamilyID:  mustGenerateUUID(t),
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := testStorage.SaveToken(ctx, rt2)
	require.NoError(t, err)

	err = testStorage.RevokeByUserID(ctx, user1.ID)
	require.NoError(t, err)

	// user1 tokens revoked.
	got1, err := testStorage.GetByHash(ctx, crypto.HashToken("user1-token-1"))
	require.NoError(t, err)
	assert.True(t, got1.Revoked)

	got2, err := testStorage.GetByHash(ctx, crypto.HashToken("user1-token-2"))
	require.NoError(t, err)
	assert.True(t, got2.Revoked)

	// user2 token NOT revoked.
	gotU2, err := testStorage.GetByHash(ctx, crypto.HashToken("user2-token"))
	require.NoError(t, err)
	assert.False(t, gotU2.Revoked)
}

// --- OAuthClient Repository ---

func createTestOAuthClient(t *testing.T, ctx context.Context, name string) *model.OAuthClient {
	t.Helper()
	client := &model.OAuthClient{
		SecretHash:     "$2a$10$testbcrypthash",
		Name:           name,
		RedirectURIs:   []string{"https://example.com/callback"},
		AllowedScopes:  []string{"openid", "profile"},
		IsConfidential: true,
	}
	err := testStorage.CreateClient(ctx, client)
	require.NoError(t, err)
	return client
}

func TestStorage_CreateClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restoreDB(t)

		client := &model.OAuthClient{
			SecretHash:     "$2a$10$somebcrypthash",
			Name:           "Test App",
			RedirectURIs:   []string{"https://app.example.com/callback"},
			AllowedScopes:  []string{"openid", "profile", "email"},
			IsConfidential: true,
		}
		err := testStorage.CreateClient(t.Context(), client)
		require.NoError(t, err)

		assert.NotEmpty(t, client.ID, "ID should be set by DB")
		assert.False(t, client.CreatedAt.IsZero(), "CreatedAt should be set")
	})

	t.Run("success with nil arrays", func(t *testing.T) {
		restoreDB(t)

		client := &model.OAuthClient{
			SecretHash: "$2a$10$somebcrypthash",
			Name:       "Minimal App",
		}
		err := testStorage.CreateClient(t.Context(), client)
		require.NoError(t, err)

		assert.NotEmpty(t, client.ID)
	})
}

func TestStorage_GetClientByID(t *testing.T) {
	restoreDB(t)
	ctx := t.Context()

	created := createTestOAuthClient(t, ctx, "Lookup App")

	t.Run("found", func(t *testing.T) {
		got, err := testStorage.GetClientByID(ctx, created.ID)
		require.NoError(t, err)

		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "$2a$10$testbcrypthash", got.SecretHash)
		assert.Equal(t, "Lookup App", got.Name)
		assert.Equal(t, []string{"https://example.com/callback"}, got.RedirectURIs)
		assert.Equal(t, []string{"openid", "profile"}, got.AllowedScopes)
		assert.True(t, got.IsConfidential)
		assert.False(t, got.CreatedAt.IsZero())
	})

	t.Run("not found", func(t *testing.T) {
		_, err := testStorage.GetClientByID(ctx, "00000000-0000-0000-0000-000000000000")
		require.ErrorIs(t, err, domainerrors.ErrOAuthClientNotFound)
	})
}
