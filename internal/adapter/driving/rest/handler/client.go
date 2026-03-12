package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type OAuthService interface {
	Create(ctx context.Context, name string, redirectURIs, allowedScopes []string, isConfidential bool) (string, string, error)
	GetByID(ctx context.Context, id string) (*model.OAuthClient, error)
}

type OAuthClientHandler struct {
	svc OAuthService
	log *zap.Logger
}

func NewOAuthClientHandler(svc OAuthService, log *zap.Logger) *OAuthClientHandler {
	return &OAuthClientHandler{
		svc: svc,
		log: log,
	}
}

func (h *OAuthClientHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest

	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	id, secret, err := h.svc.Create(r.Context(), req.Name, req.RedirectURIs, req.AllowedScopes, req.IsConfidential)
	if err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}

	respondJSON(w, http.StatusCreated, &createClientResponse{
		ClientID:     id,
		ClientSecret: secret,
	})
}

func (h *OAuthClientHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}

	respondJSON(w, http.StatusOK, &clientResponse{
		ClientID:       client.ID,
		Name:           client.Name,
		RedirectURIs:   client.RedirectURIs,
		AllowedScopes:  client.AllowedScopes,
		IsConfidential: client.IsConfidential,
	})
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
