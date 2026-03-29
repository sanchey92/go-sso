//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/sanchey92/sso/internal/adapter/driven/email"
	"github.com/sanchey92/sso/internal/adapter/driven/encryptor"
	"github.com/sanchey92/sso/internal/adapter/driven/hasher"
	jwtadapter "github.com/sanchey92/sso/internal/adapter/driven/jwt"
	"github.com/sanchey92/sso/internal/adapter/driven/postgres"
	"github.com/sanchey92/sso/internal/adapter/driven/provider"
	"github.com/sanchey92/sso/internal/adapter/driven/redis"
	"github.com/sanchey92/sso/internal/adapter/driving/rest"
	authhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/auth"
	clienthandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client"
	discoveryhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/discovery"
	federationhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/federation"
	jwkshandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/jwks"
	magiclinkhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/magiclink"
	mfahandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa"
	oauthhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	tokenhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	userhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	userinfohandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/userinfo"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/internal/usecase/auth"
	"github.com/sanchey92/sso/internal/usecase/client"
	"github.com/sanchey92/sso/internal/usecase/federation"
	"github.com/sanchey92/sso/internal/usecase/magiclink"
	"github.com/sanchey92/sso/internal/usecase/mfa"
	"github.com/sanchey92/sso/internal/usecase/oauth"
	"github.com/sanchey92/sso/internal/usecase/token"
	"github.com/sanchey92/sso/internal/usecase/user"
)

var (
	ts         *httptest.Server // HTTP-сервер для E2E-запросов
	httpClient *http.Client     // HTTP-клиент (не следует за редиректами)
	baseURL    string           // URL тестового сервера

	// Прямой доступ к инфраструктуре (для хелперов)
	testRedisAddr string
	testPGConnStr string

	// Для snapshot/restore
	pgContainer    *tcpostgres.PostgresContainer
	redisContainer *tcredis.RedisContainer
)

// testDeps хранит зависимости, которые нужны хелперам (Redis, Storage).
// В отличие от serviceProvider — это тестовая структура.
var testDeps struct {
	storage          *postgres.Storage
	cache            *redis.Cache
	magicLinkCapture *testMagicLinkCapture
}

// testMagicLinkCapture captures magic link tokens for E2E tests.
// email.LogSender logs to zap.NewNop() so tokens are lost — this wrapper saves them.
type testMagicLinkCapture struct {
	mu    sync.Mutex
	token string
}

func (c *testMagicLinkCapture) SendMagicLinkEmail(_ context.Context, _, token string) error {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
	return nil
}

func (c *testMagicLinkCapture) getToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// Mock OAuth provider servers for federation E2E tests.
var (
	mockTokenSrv    *httptest.Server
	mockUserInfoSrv *httptest.Server
)

var mockGoogleUser struct {
	mu   sync.Mutex
	info map[string]any
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgCtr, pgConnStr := mustStartPostgres(ctx)
	pgContainer = pgCtr
	testPGConnStr = pgConnStr

	// 2. Миграции
	mustRunMigrations(pgConnStr)

	// 3. Snapshot для restore между тестами
	mustCreateSnapshot(ctx, pgCtr)

	// 4. Redis container
	redisCtr, redisAddr := mustStartRedis(ctx)
	redisContainer = redisCtr
	testRedisAddr = redisAddr

	// 5. Mock OAuth providers for federation
	mockTokenSrv, mockUserInfoSrv = mustSetupMockProviders()

	// 6. Wiring + httptest.NewServer
	ts = mustSetupServer(pgConnStr, redisAddr)
	baseURL = ts.URL

	// 7. HTTP-клиент (НЕ следует за редиректами — важно для OAuth!)
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 8. Запуск тестов
	code := m.Run()

	// 9. Cleanup
	ts.Close()
	mockTokenSrv.Close()
	mockUserInfoSrv.Close()
	_ = pgCtr.Terminate(ctx)
	_ = redisCtr.Terminate(ctx)

	os.Exit(code)
}

func mustStartPostgres(ctx context.Context) (*tcpostgres.PostgresContainer, string) {
	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("sso_e2e"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		panic("failed to start postgres: " + err.Error())
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic("failed to get postgres connection string: " + err.Error())
	}

	return ctr, connStr
}

func init() {
	// testcontainers postgres module uses "postgres" driver name for snapshot/restore;
	// pgx/v5/stdlib registers as "pgx", so re-register the same driver as "postgres".
	db, err := sql.Open("pgx", "")
	if err == nil {
		sql.Register("postgres", db.Driver())
		db.Close()
	}
}

func mustRunMigrations(connStr string) {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		panic("failed to open sql connection: " + err.Error())
	}
	defer db.Close()

	// Путь относительный от test/e2e/ до корня проекта
	if err := goose.Up(db, "../../migrations"); err != nil {
		panic("failed to run migrations: " + err.Error())
	}
}

func mustCreateSnapshot(ctx context.Context, ctr *tcpostgres.PostgresContainer) {
	if err := ctr.Snapshot(ctx, tcpostgres.WithSnapshotName("clean")); err != nil {
		panic("failed to create snapshot: " + err.Error())
	}
}

func mustStartRedis(ctx context.Context) (*tcredis.RedisContainer, string) {
	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		panic("failed to start redis: " + err.Error())
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		panic("failed to get redis host: " + err.Error())
	}
	port, err := ctr.MappedPort(ctx, "6379")
	if err != nil {
		panic("failed to get redis port: " + err.Error())
	}

	return ctr, fmt.Sprintf("%s:%s", host, port.Port())
}

func mustSetupServer(pgConnStr, redisAddr string) *httptest.Server {
	log := zap.NewNop() // Тесты не шумят в stdout

	// --- Infrastructure ---

	ctx := context.Background()

	storage, err := postgres.New(ctx, &postgres.Config{
		DSN:             pgConnStr,
		MaxConns:        5,
		MinConns:        1,
		MaxConnLifetime: time.Minute,
		MaxConnIdleTime: time.Minute,
	}, log)
	if err != nil {
		panic("failed to create storage: " + err.Error())
	}

	cache, err := redis.NewCache(&redis.Config{
		Address:         redisAddr,
		DB:              0,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolSize:        5,
		MinIdleConns:    1,
		ConnMaxIdleTime: time.Minute,
	}, log)
	if err != nil {
		panic("failed to create cache: " + err.Error())
	}

	jwtService, err := jwtadapter.NewService(&jwtadapter.Config{
		Issuer:         "test-sso",
		AccessTokenTTL: 15 * time.Minute,
		MFATokenTTL:    5 * time.Minute,
	})
	if err != nil {
		panic("failed to create jwt service: " + err.Error())
	}

	h := hasher.New(hasher.DefaultConfig())
	emailSender := email.NewLogSender(log, "http://localhost:0") // dummy URL

	enc, err := encryptor.New([]byte("test-encryption-key-32-bytes!!!!")) // exactly 32 bytes
	if err != nil {
		panic("failed to create encryptor: " + err.Error())
	}

	httputil.SetMaxBodySize(1 << 20) // 1MB

	// --- Use Cases ---

	tokenValidator := jwtadapter.NewTokenValidator(jwtService)
	tokenService := token.New(
		jwtService, storage,
		15*time.Minute, // accessTTL
		168*time.Hour,  // refreshTTL
		"sso",          // audience
		log,
	)

	userService := user.New(
		storage, h, cache, emailSender, tokenValidator, storage,
		24*time.Hour, // verificationTTL
		1*time.Hour,  // resetTTL
		log,
	)

	mfaService := mfa.New(storage, storage, enc, storage, storage, "test-sso", 1, log)

	mlCapture := &testMagicLinkCapture{}
	magicLinkService := magiclink.New(storage, cache, mlCapture, tokenService, 15*time.Minute, log)

	authService := auth.New(storage, h, tokenService, tokenService, jwtService, mfaService, mfaService, log)
	clientService := client.New(storage, log)
	oauthService := oauth.New(storage, clientService, cache, tokenService, 60*time.Second, log)

	// --- Federation ---

	googleProvider := provider.NewGoogleProvider(
		"test-google-id", "test-google-secret", "http://localhost/callback",
		provider.WithEndpoint(oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  mockTokenSrv.URL,
			AuthStyle: oauth2.AuthStyleInParams,
		}),
		provider.WithUserInfoURL(mockUserInfoSrv.URL),
	)

	providers := map[string]federation.IdentityProvider{
		"google": googleProvider,
	}

	federationService := federation.New(providers, storage, tokenService, cache, 10*time.Minute, log)

	jwksProvider := func() ([]byte, error) {
		return json.Marshal(jwtService.GetJWKS())
	}

	// --- HTTP Handlers ---

	handlers := rest.Handlers{
		User:   userhandler.NewHandler(userService, log),
		Auth:   authhandler.NewHandler(authService, log),
		Token:  tokenhandler.NewHandler(tokenService, log),
		Client: clienthandler.NewHandler(clientService, log),
		OAuth:  oauthhandler.NewHandler(oauthService, oauthService, tokenService, tokenService, log),
		JWKS:   jwkshandler.NewHandler(jwksProvider, log),
		Discovery: discoveryhandler.NewHandler(&discoveryhandler.Config{
			Issuer:  "test-sso",
			BaseURL: "TEST_BASE_URL", // будет заменён после создания httptest.Server
		}),
		UserInfo:   userinfohandler.NewHandler(userService, log),
		Federation: federationhandler.NewHandler(federationService, federationService, log),
		MFA:        mfahandler.New(mfaService, tokenValidator, authService, log),
		MagicLink:  magiclinkhandler.NewHandler(magicLinkService, magicLinkService, log),
	}

	// Rate limiter: в E2E-тестах используем noop (не блокируем)
	noopRateLimit := func(next http.Handler) http.Handler { return next }

	corsCfg := middleware.CORSConfig{
		AllowOrigins:  "*",
		AllowMethods:  "GET, POST, PUT, DELETE, OPTIONS",
		AllowHeaders:  "Content-Type, Authorization, X-Request-ID",
		ExposeHeaders: "X-Request-ID",
		MaxAge:        "86400",
	}

	srv := rest.NewServer(&rest.Config{
		Host:         "127.0.0.1",
		Port:         0,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}, handlers, noopRateLimit, noopRateLimit, noopRateLimit, corsCfg, log)

	// Сохраняем зависимости для хелперов
	testDeps.storage = storage
	testDeps.cache = cache
	testDeps.magicLinkCapture = mlCapture

	// httptest.NewServer использует Handler() — именно для этого мы его добавили
	return httptest.NewServer(srv.Handler())
}

func mustSetupMockProviders() (tokenSrv, userInfoSrv *httptest.Server) {
	tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-google-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))

	userInfoSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockGoogleUser.mu.Lock()
		info := mockGoogleUser.info
		mockGoogleUser.mu.Unlock()

		if info == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}))

	return tokenSrv, userInfoSrv
}
