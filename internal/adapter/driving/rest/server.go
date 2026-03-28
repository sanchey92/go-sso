package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/auth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/discovery"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/federation"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/jwks"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/mfa"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/userinfo"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
)

type Config struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Handlers groups all HTTP handler dependencies for the server.
type Handlers struct {
	User       *user.Handler
	Auth       *auth.Handler
	Token      *token.Handler
	Client     *client.Handler
	OAuth      *oauth.Handler
	JWKS       *jwks.Handler
	Discovery  *discovery.Handler
	UserInfo   *userinfo.Handler
	Federation *federation.Handler
	MFA        *mfa.Handler
}

type Server struct {
	httpServer     *http.Server
	router         chi.Router
	handlers       Handlers
	loginRateLimit func(http.Handler) http.Handler
	mfaRateLimit   func(http.Handler) http.Handler
	corsConfig     middleware.CORSConfig
	log            *zap.Logger
}

func NewServer(
	cfg *Config,
	h Handlers,
	loginRateLimit func(http.Handler) http.Handler,
	mfaRateLimiter func(http.Handler) http.Handler,
	corsCfg middleware.CORSConfig,
	log *zap.Logger,
) *Server {
	r := chi.NewRouter()

	s := &Server{
		router:         r,
		handlers:       h,
		loginRateLimit: loginRateLimit,
		mfaRateLimit:   mfaRateLimiter,
		corsConfig:     corsCfg,
		log:            log,
	}

	s.setupMiddleware()
	s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.Recovery(s.log))
	s.router.Use(middleware.Logging(s.log))
	s.router.Use(middleware.CORS(s.corsConfig))
}

func (s *Server) setupRoutes() {
	s.router.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", s.handlers.User.Register)

		r.With(s.loginRateLimit).Post("/login", s.handlers.Auth.Login)

		r.Post("/token/refresh", s.handlers.Token.Refresh)
		r.Post("/token/revoke", s.handlers.Token.Revoke)
		r.Post("/email/verify", s.handlers.User.VerifyEmail)
		r.Post("/password/reset-request", s.handlers.User.RequestPasswordReset)
		r.Post("/password/reset", s.handlers.User.ResetPassword)

		r.Post("/mfa/totp/setup", s.handlers.MFA.Setup)
		r.Post("/mfa/totp/verify-setup", s.handlers.MFA.VerifySetup)
		r.Delete("/mfa/totp", s.handlers.MFA.Disable)

		r.With(s.mfaRateLimit).Post("/mfa/totp/verify", s.handlers.MFA.VerifyTOTP)
		r.With(s.mfaRateLimit).Post("/mfa/recovery/verify", s.handlers.MFA.VerifyRecovery)
	})

	s.router.Route("/api/v1/oauth", func(r chi.Router) {
		r.Get("/authorize", s.handlers.OAuth.Authorize)
		r.Post("/token", s.handlers.OAuth.Token)
		r.Post("/revoke", s.handlers.OAuth.Revoke)
		r.Post("/userinfo", s.handlers.UserInfo.UserInfo)
		r.Get("/clients/{id}", s.handlers.Client.GetByID)
		r.Post("/clients/", s.handlers.Client.Create)
	})

	s.router.Route("/api/v1/federation/{provider}", func(r chi.Router) {
		r.Get("/authorize", s.handlers.Federation.Authorize)
		r.Get("/callback", s.handlers.Federation.Callback)
	})

	// OIDC Discovery + JWKS — must be at well-known paths (root level, not under /api/v1)
	s.router.Get("/.well-known/openid-configuration", s.handlers.Discovery.Discovery)
	s.router.Get("/.well-known/jwks.json", s.handlers.JWKS.JWKS)

	s.router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`)) //nolint:gosec // error writing response body is unrecoverable
	})
}

func (s *Server) Start() error {
	s.log.Info("starting HTTP server", zap.String("addr", s.httpServer.Addr))
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.log.Info("stopping HTTP server")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	return s.router
}
