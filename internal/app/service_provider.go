package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"

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
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	jwkshandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/jwks"
	mfahandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa"
	oauthhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	tokenhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	userhandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	userinfohandler "github.com/sanchey92/sso/internal/adapter/driving/rest/handler/userinfo"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/internal/usecase/auth"
	"github.com/sanchey92/sso/internal/usecase/client"
	"github.com/sanchey92/sso/internal/usecase/federation"
	"github.com/sanchey92/sso/internal/usecase/mfa"
	"github.com/sanchey92/sso/internal/usecase/oauth"
	"github.com/sanchey92/sso/internal/usecase/token"
	"github.com/sanchey92/sso/internal/usecase/user"
	"github.com/sanchey92/sso/pkg/logger"
)

type serviceProvider struct {
	log        *zap.Logger
	storage    *postgres.Storage
	cache      *redis.Cache
	httpServer *rest.Server
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
}

func newServiceProvider(cfg *config.Config) (*serviceProvider, error) {
	log := initLogger(cfg.Observability.Log)

	storage, err := initPostgres(&cfg.Database.Postgres, log)
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

	httpServer := initHTTPServer(cfg, uc, a, jwksProvider, cache, log)

	return &serviceProvider{
		log:        log,
		storage:    storage,
		cache:      cache,
		httpServer: httpServer,
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
	mfaSvc := mfa.New(storage, storage, a.encryptor, storage, storage, cfg.MFA.TOTP.Issuer, uint(cfg.MFA.TOTP.Skew), log)

	authSvc := auth.New(storage, a.hasher, tokenSvc, tokenSvc, a.jwtService, mfaSvc, mfaSvc, log)
	clientSvc := client.New(storage, log)
	oauthSvc := oauth.New(storage, clientSvc, cache, tokenSvc, cfg.OAuth.AuthCodeTTL, log)
	federationSvc := federation.New(initProviders(cfg.Federation), storage, tokenSvc, cache, cfg.Federation.StateTTL, log)

	return &usecases{
		auth:       authSvc,
		user:       userSvc,
		token:      tokenSvc,
		client:     clientSvc,
		oauth:      oauthSvc,
		federation: federationSvc,
		mfa:        mfaSvc,
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

func initPostgres(cfg *config.PostgresConfig, log *zap.Logger) (*postgres.Storage, error) {
	s, err := postgres.New(context.Background(), &postgres.Config{
		DSN:             cfg.DSN,
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
		MaxConnIdleTime: cfg.MaxConnIdleTime,
	}, log)
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
	uc *usecases,
	a *adapters,
	jwksProvider func() ([]byte, error),
	cache *redis.Cache,
	log *zap.Logger,
) *rest.Server {
	handlers := rest.Handlers{
		User:   userhandler.NewHandler(uc.user, log),
		Auth:   authhandler.NewHandler(uc.auth, log),
		Token:  tokenhandler.NewHandler(uc.token, log),
		Client: clienthandler.NewHandler(uc.client, log),
		OAuth:  oauthhandler.NewHandler(uc.oauth, uc.oauth, uc.token, uc.token, log),
		JWKS:   jwkshandler.NewHandler(jwksProvider, log),
		Discovery: discoveryhandler.NewHandler(&discoveryhandler.Config{
			Issuer:  cfg.Auth.Issuer,
			BaseURL: cfg.Server.HTTP.BaseURL,
		}),
		UserInfo:   userinfohandler.NewHandler(uc.user, log),
		Federation: federationhandler.NewHandler(uc.federation, uc.federation, log),
		MFA:        mfahandler.New(uc.mfa, a.tokenValidator, uc.auth, log),
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

	corsCfg := middleware.CORSConfig{
		AllowOrigins:  cfg.Security.CORS.AllowOrigins,
		AllowMethods:  cfg.Security.CORS.AllowMethods,
		AllowHeaders:  cfg.Security.CORS.AllowHeaders,
		ExposeHeaders: cfg.Security.CORS.ExposeHeaders,
		MaxAge:        cfg.Security.CORS.MaxAge,
	}

	return rest.NewServer(&rest.Config{
		Host:         cfg.Server.HTTP.Host,
		Port:         cfg.Server.HTTP.Port,
		ReadTimeout:  cfg.Server.HTTP.ReadTimeout,
		WriteTimeout: cfg.Server.HTTP.WriteTimeout,
	}, handlers, loginRateLimit, mfaRateLimit, corsCfg, log)
}
