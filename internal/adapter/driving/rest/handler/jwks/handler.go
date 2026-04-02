package jwks

import (
	"net/http"

	"go.uber.org/zap"
)

type Handler struct {
	getJWKS func() ([]byte, error)
	log     *zap.Logger
}

func NewHandler(getJWKS func() ([]byte, error), log *zap.Logger) *Handler {
	return &Handler{
		getJWKS: getJWKS,
		log:     log,
	}
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.getJWKS()
	if err != nil {
		h.log.Error("failed to get JWKS", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) //nolint:gosec // error writing response body is unrecoverable
}
