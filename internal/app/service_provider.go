package app

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driven/email"
	"github.com/sanchey92/sso/internal/adapter/driven/hasher"
	jwtadapter "github.com/sanchey92/sso/internal/adapter/driven/jwt"
	"github.com/sanchey92/sso/internal/adapter/driven/postgres"
	"github.com/sanchey92/sso/internal/adapter/driven/redis"
	"github.com/sanchey92/sso/internal/adapter/driving/rest"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/internal/usecase/auth"
	"github.com/sanchey92/sso/internal/usecase/client"
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

	jwtService, err := initJWT(&cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}

	h := hasher.New(hasher.DefaultConfig())
	emailSender := email.NewLogSender(log, cfg.Server.HTTP.BaseURL)

	handler.SetMaxBodySize(cfg.Server.HTTP.MaxBodySize)

	tokenService := token.New(jwtService, storage, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL, cfg.Auth.Audience, log)
	userService := user.New(storage, h, cache, emailSender, storage, cfg.Auth.VerificationTTL, cfg.Auth.ResetTTL, log)
	authService := auth.New(storage, h, tokenService, log)
	clientService := client.New(storage, log)

	httpServer := initHTTPServer(cfg, userService, authService, tokenService, clientService, cache, log)

	return &serviceProvider{
		log:        log,
		storage:    storage,
		cache:      cache,
		httpServer: httpServer,
	}, nil
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
		Issuer:         cfg.Issuer,
		AccessTokenTTL: cfg.AccessTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("jwtadapter.NewService: %w", err)
	}
	return s, nil
}

func initHTTPServer(
	cfg *config.Config,
	userSvc *user.Service,
	authSvc *auth.Service,
	tokenSvc *token.Service,
	clientSvc *client.Service,
	cache *redis.Cache,
	log *zap.Logger,
) *rest.Server {
	userHandler := handler.NewUserHandler(userSvc, log)
	authHandler := handler.NewAuthHandler(authSvc, log)
	tokenHandler := handler.NewTokenHandler(tokenSvc, log)
	oauthHandler := handler.NewOAuthClientHandler(clientSvc, log)

	loginRateLimit := middleware.RateLimit(
		cache,
		cfg.Security.RateLimit.Login.MaxAttempts,
		cfg.Security.RateLimit.Login.Window,
		func(r *http.Request) string {
			return "rate:login:" + middleware.ExtractIP(r)
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
	}, userHandler, authHandler, tokenHandler, oauthHandler, loginRateLimit, corsCfg, log)
}
