package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
)

type Config struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type Server struct {
	httpServer   *http.Server
	router       chi.Router
	userHandler  *handler.UserHandler
	authHandler  *handler.AuthHandler
	tokenHandler *handler.TokenHandler
	log          *zap.Logger
}

func NewServer(
	cfg *Config,
	userH *handler.UserHandler,
	authH *handler.AuthHandler,
	tokenH *handler.TokenHandler,
	log *zap.Logger,
) *Server {
	r := chi.NewRouter()

	s := &Server{
		router:       r,
		userHandler:  userH,
		authHandler:  authH,
		tokenHandler: tokenH,
		log:          log,
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
	s.router.Use(middleware.CORS)
}

func (s *Server) setupRoutes() {
	s.router.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", s.userHandler.Register)
		r.Post("/login", s.authHandler.Login)
		r.Post("/token/refresh", s.tokenHandler.Refresh)
		r.Post("/token/revoke", s.tokenHandler.Revoke)
		r.Post("/email/verify", s.userHandler.VerifyEmail)
	})

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
