//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/sanchey92/sso/pkg/crypto"
)

func restoreDB(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	// Закрываем старый сервер и пул соединений
	ts.Close()
	testDeps.storage.Close()

	err := pgContainer.Restore(ctx, tcpostgres.WithSnapshotName("clean"))
	require.NoError(t, err, "failed to restore database snapshot")

	// Пересоздаём сервер целиком (хендлеры держат ссылки на старый пул)
	ts = mustSetupServer(testPGConnStr, testRedisAddr)
	baseURL = ts.URL
}

func flushRedis(t *testing.T) {
	t.Helper()

	rdb := goredis.NewClient(&goredis.Options{Addr: testRedisAddr})
	defer rdb.Close()
	require.NoError(t, rdb.FlushDB(t.Context()).Err())
}

func postJSON(t *testing.T, path string, body any) *http.Response {
	t.Helper()

	data, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := httpClient.Post(baseURL+path, "application/json", bytes.NewReader(data))
	require.NoError(t, err)

	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()

	var result T
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	return result
}

func postForm(t *testing.T, path string, values url.Values) *http.Response {
	t.Helper()

	resp, err := httpClient.PostForm(baseURL+path, values)
	require.NoError(t, err)

	return resp
}

func getWithQuery(t *testing.T, path string, params url.Values) *http.Response {
	t.Helper()

	u := baseURL + path + "?" + params.Encode()
	resp, err := httpClient.Get(u)
	require.NoError(t, err)

	return resp
}

func scanRedisKey(t *testing.T, pattern string) string {
	t.Helper()

	rdb := goredis.NewClient(&goredis.Options{Addr: testRedisAddr})
	defer rdb.Close()

	var cursor uint64
	keys, _, err := rdb.Scan(t.Context(), cursor, pattern, 10).Result()
	require.NoError(t, err)
	require.NotEmpty(t, keys, "no keys found matching pattern: "+pattern)

	return keys[0]
}

func getVerificationToken(t *testing.T) string {
	t.Helper()

	key := scanRedisKey(t, "verify:*")
	return strings.TrimPrefix(key, "verify:")
}

func registerUser(t *testing.T, email, password string) string {
	t.Helper()

	resp := postJSON(t, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSON[map[string]any](t, resp)
		t.Fatalf("register failed: status=%d body=%v", resp.StatusCode, body)
	}

	result := decodeJSON[map[string]string](t, resp)
	userID := result["user_id"]
	require.NotEmpty(t, userID)

	return userID
}

// verifyEmail извлекает verification token из Redis и верифицирует email.
func verifyEmail(t *testing.T) {
	t.Helper()

	token := getVerificationToken(t)

	resp := postJSON(t, "/api/v1/auth/email/verify", map[string]string{
		"token": token,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// loginUser логинит пользователя и возвращает access_token + refresh_token.
func loginUser(t *testing.T, email, password string) (accessToken, refreshToken string) {
	t.Helper()

	resp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]any](t, resp)
	return result["access_token"].(string), result["refresh_token"].(string)
}

// createOAuthClient создаёт OAuth-клиента и возвращает client_id + raw secret.
func createOAuthClient(t *testing.T, redirectURI string) (clientID, clientSecret string) {
	t.Helper()

	resp := postJSON(t, "/api/v1/oauth/clients/", map[string]any{
		"name":            "Test App",
		"redirect_uris":   []string{redirectURI},
		"allowed_scopes":  []string{"openid", "profile", "email"},
		"is_confidential": true,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	return result["client_id"], result["client_secret"]
}

func setMockGoogleUser(sub, email, name, picture string, verified bool) {
	mockGoogleUser.mu.Lock()
	defer mockGoogleUser.mu.Unlock()
	mockGoogleUser.info = map[string]any{
		"sub":            sub,
		"email":          email,
		"email_verified": verified,
		"name":           name,
		"picture":        picture,
	}
}

func federationAuthorize(t *testing.T, providerName string) string {
	t.Helper()

	resp, err := httpClient.Get(baseURL + "/api/v1/federation/" + providerName + "/authorize")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)

	u, err := url.Parse(location)
	require.NoError(t, err)

	state := u.Query().Get("state")
	require.NotEmpty(t, state, "state must be present in redirect URL")

	return state
}

func federationCallback(t *testing.T, providerName, code, state string) (accessToken, refreshToken string) {
	t.Helper()

	resp := getWithQuery(t, "/api/v1/federation/"+providerName+"/callback", url.Values{
		"code":  {code},
		"state": {state},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]any](t, resp)
	return result["access_token"].(string), result["refresh_token"].(string)
}

func getUserInfo(t *testing.T, accessToken string) map[string]any {
	t.Helper()

	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return decodeJSON[map[string]any](t, resp)
}

func postJSONWithAuth(t *testing.T, path string, body any, accessToken string) *http.Response {
	t.Helper()

	data, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+path, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	return resp
}

func deleteJSONWithAuth(t *testing.T, path string, body any, accessToken string) *http.Response {
	t.Helper()

	data, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest("DELETE", baseURL+path, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	return resp
}

// loginUserMFA логинит пользователя и возвращает либо tokens (MFA выключен),
// либо mfa_token (MFA включён).
func loginUserMFA(t *testing.T, email, password string) (accessToken, refreshToken, mfaToken string, mfaRequired bool) {
	t.Helper()

	resp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]any](t, resp)

	if mr, ok := result["mfa_required"].(bool); ok && mr {
		return "", "", result["mfa_token"].(string), true
	}
	return result["access_token"].(string), result["refresh_token"].(string), "", false
}

func getMagicLinkToken(t *testing.T) string {
	t.Helper()

	token := testDeps.magicLinkCapture.getToken()
	require.NotEmpty(t, token, "magic link token not captured")

	return token
}

func generatePKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()

	verifier, err := crypto.GenerateRandomToken(32)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge
}
