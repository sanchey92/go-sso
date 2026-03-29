package client

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type OAuthService interface {
	Create(ctx context.Context, name string, redirectURIs, allowedScopes []string, isConfidential bool) (string, string, error)
	GetByID(ctx context.Context, id string) (*model.OAuthClient, error)
}

type Handler struct {
	svc OAuthService
	log *zap.Logger
}

func NewHandler(svc OAuthService, log *zap.Logger) *Handler {
	return &Handler{
		svc: svc,
		log: log,
	}
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest

	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	id, secret, err := h.svc.Create(r.Context(), req.Name, req.RedirectURIs, req.AllowedScopes, req.IsConfidential)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, &createClientResponse{
		ClientID:     id,
		ClientSecret: secret,
	})
}

func (h *Handler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	c, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &clientResponse{
		ClientID:       c.ID,
		Name:           c.Name,
		RedirectURIs:   c.RedirectURIs,
		AllowedScopes:  c.AllowedScopes,
		IsConfidential: c.IsConfidential,
	})
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrOAuthClientNotFound):
		httputil.RespondError(w, http.StatusNotFound, "client not found", "CLIENT_NOT_FOUND")
	default:
		if errors.Unwrap(err) == nil {
			httputil.RespondError(w, http.StatusBadRequest, err.Error(), "VALIDATION_ERROR")
			return
		}
		h.log.Error("internal error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}

type createClientRequest struct {
	Name           string   `json:"name"`
	RedirectURIs   []string `json:"redirect_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	IsConfidential bool     `json:"is_confidential"`
}

type createClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type clientResponse struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	RedirectURIs   []string `json:"redirect_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	IsConfidential bool     `json:"is_confidential"`
}
