package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/internal/adapter/driven/email"
	"github.com/sanchey92/sso/internal/adapter/driven/encryptor"
	"github.com/sanchey92/sso/internal/adapter/driven/hasher"
	jwtadapter "github.com/sanchey92/sso/internal/adapter/driven/jwt"
	"github.com/sanchey92/sso/internal/adapter/driven/postgres"
	"github.com/sanchey92/sso/internal/adapter/driven/provider"
	"github.com/sanchey92/sso/internal/adapter/driven/redis"
	grpcserver "github.com/sanchey92/sso/internal/adapter/driving/grpc"
	grpchandler "github.com/sanchey92/sso/internal/adapter/driving/grpc/handler"
	"github.com/sanchey92/sso/internal/adapter/driving/grpc/interceptor"
	"github.com/sanchey92/sso/internal/adapter/driving/rest"
	authhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/auth"
	clienthandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client"
	discoveryhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/discovery"
	federationhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/federation"
	healthhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/health"
	jwkshandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/jwks"
	magiclinkhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/magiclink"
	mfahandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa"
	oauthhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	tokenhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	userhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	userinfohandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/userinfo"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/internal/usecase/auth"
	"github.com/sanchey92/sso/internal/usecase/client"
	"github.com/sanchey92/sso/internal/usecase/federation"
	"github.com/sanchey92/sso/internal/usecase/magiclink"
	"github.com/sanchey92/sso/internal/usecase/mfa"
	"github.com/sanchey92/sso/internal/usecase/oauth"
	"github.com/sanchey92/sso/internal/usecase/token"
	"github.com/sanchey92/sso/internal/usecase/user"
	"github.com/sanchey92/sso/pkg/logger"
	"github.com/sanchey92/sso/pkg/metrics"
	"github.com/sanchey92/sso/pkg/tracing"
)

type serviceProvider struct {
	log             *zap.Logger
	storage         *postgres.Storage
	cache           *redis.Cache
	httpServer      *rest.Server
	grpcServer      *grpcserver.Server
	tracingShutdown func(context.Context) error
	healthStop      func()
}

type adapters struct {
	hasher         *hasher.Hasher
	emailSender    *email.LogSender
	encryptor      *encryptor.Encryptor
	jwtService     *jwtadapter.Service
	tokenValidator *jwtadapter.TokenValidator
}

type usecases struct {
	auth       *auth.Service
	user       *user.Service
	token      *token.Service
	client     *client.Service
	oauth      *oauth.Service
	federation *federation.Service
	mfa        *mfa.Service
	magicLink  *magiclink.Service
}

func newServiceProvider(cfg *config.Config) (*serviceProvider, error) {
	log := initLogger(cfg.Observability.Log)
	m := metrics.New()

	// Tracing — инициализируем до всего остального,
	// чтобы pgx/redis/handlers видели глобальный TracerProvider
	var tracingShutdown func(context.Context) error
	if cfg.Observability.Tracing.Enabled {
		shutdown, err := tracing.New(context.Background(), &tracing.Config{
			Endpoint:       cfg.Observability.Tracing.Endpoint,
			ServiceName:    "sso",
			ServiceVersion: "1.0.0",
			SampleRate:     cfg.Observability.Tracing.SampleRate,
		})
		if err != nil {
			return nil, fmt.Errorf("tracing: %w", err)
		}
		tracingShutdown = shutdown
	}

	storage, err := initPostgres(&cfg.Database.Postgres, m, log)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	cache, err := initCache(&cfg.Database.Redis, log)
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	a, err := initAdapters(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("adapters: %w", err)
	}

	httputil.SetMaxBodySize(cfg.Server.HTTP.MaxBodySize)
	uc := initUseCases(cfg, storage, cache, a, log)

	jwksProvider := func() ([]byte, error) {
		return json.Marshal(a.jwtService.GetJWKS())
	}

	httpServer := initHTTPServer(cfg, m, uc, a, jwksProvider, storage, cache, log)
	grpcSrv, healthStop := initGRPCServer(&cfg.Server.GRPC, cfg.Observability.Log.Level, m, a, storage, cache, log)

	return &serviceProvider{
		log:             log,
		storage:         storage,
		cache:           cache,
		httpServer:      httpServer,
		grpcServer:      grpcSrv,
		tracingShutdown: tracingShutdown,
		healthStop:      healthStop,
	}, nil
}

func initAdapters(cfg *config.Config, log *zap.Logger) (*adapters, error) {
	jwtSvc, err := initJWT(&cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}

	enc, err := encryptor.New([]byte(cfg.Security.EncryptionKey))
	if err != nil {
		return nil, fmt.Errorf("encryptor: %w", err)
	}

	return &adapters{
		hasher:         hasher.New(hasher.DefaultConfig()),
		emailSender:    email.NewLogSender(log, cfg.Server.HTTP.BaseURL),
		encryptor:      enc,
		jwtService:     jwtSvc,
		tokenValidator: jwtadapter.NewTokenValidator(jwtSvc),
	}, nil
}

func initUseCases(cfg *config.Config, storage *postgres.Storage, cache *redis.Cache, a *adapters, log *zap.Logger) *usecases {
	tokenSvc := token.New(a.jwtService, storage, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL, cfg.Auth.Audience, log)
	userSvc := user.New(storage, a.hasher, cache, a.emailSender, a.tokenValidator, storage, cfg.Auth.VerificationTTL, cfg.Auth.ResetTTL, log)
	mfaSvc := mfa.New(storage, storage, a.encryptor, storage, storage, cfg.MFA.TOTP.Issuer, uint(cfg.MFA.TOTP.Skew), log) //nolint:gosec // skew is a small config value, overflow impossible

	authSvc := auth.New(storage, a.hasher, tokenSvc, tokenSvc, a.jwtService, mfaSvc, mfaSvc, log)
	clientSvc := client.New(storage, log)
	oauthSvc := oauth.New(storage, clientSvc, cache, tokenSvc, cfg.OAuth.AuthCodeTTL, log)
	federationSvc := federation.New(initProviders(cfg.Federation), storage, tokenSvc, cache, cfg.Federation.StateTTL, log)
	magicLinkSvc := magiclink.New(storage, cache, a.emailSender, tokenSvc, cfg.Auth.MagicLinkTTL, log)

	return &usecases{
		auth:       authSvc,
		user:       userSvc,
		token:      tokenSvc,
		client:     clientSvc,
		oauth:      oauthSvc,
		federation: federationSvc,
		mfa:        mfaSvc,
		magicLink:  magicLinkSvc,
	}
}

func initProviders(cfg config.FederationConfig) map[string]federation.IdentityProvider {
	return map[string]federation.IdentityProvider{
		"google": provider.NewGoogleProvider(cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.RedirectURL),
		"github": provider.NewGitHubProvider(cfg.GitHub.ClientID, cfg.GitHub.ClientSecret, cfg.GitHub.RedirectURL),
	}
}

func initLogger(cfg config.LogConfig) *zap.Logger {
	return logger.New(&logger.Config{
		Level:  cfg.Level,
		Format: cfg.Format,
	})
}

func initPostgres(cfg *config.PostgresConfig, m *metrics.Metrics, log *zap.Logger) (*postgres.Storage, error) {
	s, err := postgres.New(context.Background(), &postgres.Config{
		DSN:             cfg.DSN,
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
		MaxConnIdleTime: cfg.MaxConnIdleTime,
	}, m, log)
	if err != nil {
		return nil, fmt.Errorf("postgres.New: %w", err)
	}
	return s, nil
}

func initCache(cfg *config.RedisConfig, log *zap.Logger) (*redis.Cache, error) {
	c, err := redis.NewCache(&redis.Config{
		Address:         cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		DialTimeout:     cfg.DialTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		ConnMaxIdleTime: cfg.ConnMaxIdleTime,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("redis.NewCache: %w", err)
	}
	return c, nil
}

func initJWT(cfg *config.AuthConfig) (*jwtadapter.Service, error) {
	s, err := jwtadapter.NewService(&jwtadapter.Config{
		Issuer:          cfg.Issuer,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		MFATokenTTL:     cfg.MFATokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("jwtadapter.NewService: %w", err)
	}
	return s, nil
}

func initHTTPServer(
	cfg *config.Config,
	m *metrics.Metrics,
	uc *usecases,
	a *adapters,
	jwksProvider func() ([]byte, error),
	storage *postgres.Storage,
	cache *redis.Cache,
	log *zap.Logger,
) *rest.Server {
	handlers := rest.Handlers{
		User:   userhandler.NewHandler(uc.user, log),
		Auth:   authhandler.NewHandler(uc.auth, m, log),
		Token:  tokenhandler.NewHandler(uc.token, log),
		Client: clienthandler.NewHandler(uc.client, log),
		OAuth:  oauthhandler.NewHandler(uc.oauth, uc.oauth, uc.token, uc.token, log),
		JWKS:   jwkshandler.NewHandler(jwksProvider, log),
		Discovery: discoveryhandler.NewHandler(&discoveryhandler.Config{
			Issuer:  cfg.Auth.Issuer,
			BaseURL: cfg.Server.HTTP.BaseURL,
		}),
		UserInfo:   userinfohandler.NewHandler(uc.user, log),
		Federation: federationhandler.NewHandler(uc.federation, uc.federation, m, log),
		MFA:        mfahandler.New(uc.mfa, a.tokenValidator, uc.auth, m, log),
		MagicLink:  magiclinkhandler.NewHandler(uc.magicLink, uc.magicLink, m, log),
		Health:     healthhandler.NewHandler(storage, cache),
	}

	loginRateLimit := middleware.RateLimit(
		cache,
		cfg.Security.RateLimit.Login.MaxAttempts,
		cfg.Security.RateLimit.Login.Window,
		func(r *http.Request) string {
			return "rate:login:" + middleware.ExtractIP(r)
		},
		log,
	)

	mfaRateLimit := middleware.RateLimit(
		cache,
		cfg.Security.RateLimit.TOTP.MaxAttempts,
		cfg.Security.RateLimit.TOTP.Window,
		func(r *http.Request) string {
			return "rate:mfa:" + middleware.ExtractIP(r)
		},
		log,
	)

	magicLinkRateLimit := middleware.RateLimit(
		cache,
		cfg.Security.RateLimit.MagicLink.MaxAttempts,
		cfg.Security.RateLimit.MagicLink.Window,
		func(r *http.Request) string {
			return "rate:magic_link:" + middleware.ExtractIP(r)
		},
		log,
	)

	corsCfg := middleware.CORSConfig{
		AllowOrigins:  cfg.Security.CORS.AllowOrigins,
		AllowMethods:  cfg.Security.CORS.AllowMethods,
		AllowHeaders:  cfg.Security.CORS.AllowHeaders,
		ExposeHeaders: cfg.Security.CORS.ExposeHeaders,
		MaxAge:        cfg.Security.CORS.MaxAge,
	}

	hstsCfg := middleware.HSTSConfig{
		Enabled: cfg.Security.HSTS.Enabled,
		MaxAge:  cfg.Security.HSTS.MaxAge,
	}

	return rest.NewServer(&rest.Config{
		Host:         cfg.Server.HTTP.Host,
		Port:         cfg.Server.HTTP.Port,
		MetricsPort:  cfg.Observability.Metrics.Port,
		ReadTimeout:  cfg.Server.HTTP.ReadTimeout,
		WriteTimeout: cfg.Server.HTTP.WriteTimeout,
	}, handlers, m, loginRateLimit, mfaRateLimit, magicLinkRateLimit, corsCfg, hstsCfg, log)
}

func initGRPCServer(
	cfg *config.GRPCServerConfig,
	logLevel string,
	m *metrics.Metrics,
	a *adapters,
	storage *postgres.Storage,
	cache *redis.Cache,
	log *zap.Logger,
) (*grpcserver.Server, func()) {
	srv := grpcserver.NewServer(&grpcserver.Config{
		Host: cfg.Host,
		Port: cfg.Port,
	}, log,
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			interceptor.AuthInterceptor(cfg.APIKey),
			interceptor.LoggingInterceptor(log),
			interceptor.MetricsInterceptor(m),
		))

	h := grpchandler.New(a.jwtService, storage, cache, cfg.IntrospectionCacheTTL, log)
	srv.RegisterService(&ssov1.SSOInternalService_ServiceDesc, h)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv.GRPCServer(), healthServer)

	stop := startHealthChecker(cfg.HealthCheckInterval, storage, cache, healthServer, log)

	if logLevel == "debug" {
		srv.EnableReflection()
	}

	return srv, stop
}

func startHealthChecker(
	interval time.Duration,
	storage *postgres.Storage,
	cache *redis.Cache,
	hs *health.Server,
	log *zap.Logger,
) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	check := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		pgErr := storage.Ping(ctx)
		redisErr := cache.Ping(ctx)

		if pgErr != nil || redisErr != nil {
			log.Warn("health check failed", zap.Error(pgErr), zap.Error(redisErr))
			hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
			return
		}
		hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	}

	check()

	go func() {
		for {
			select {
			case <-ticker.C:
				check()
			case <-done:
				ticker.Stop()
				hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
				return
			}
		}
	}()

	return func() { close(done) }
}
