package magiclink

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
	"github.com/sanchey92/sso/pkg/metrics"
)

type LinkRequester interface {
	RequestMagicLink(ctx context.Context, email string) error
}

type LinkVerifier interface {
	VerifyMagicLink(ctx context.Context, token string) (*model.TokenPair, error)
}

type requestMagicLinkRequest struct {
	Email string `json:"email"`
}

type verifyMagicLinkRequest struct {
	Token string `json:"token"`
}

type messageResponse struct {
	Message string `json:"message"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type Handler struct {
	requester LinkRequester
	verifier  LinkVerifier
	metrics   *metrics.Metrics
	log       *zap.Logger
}

func NewHandler(r LinkRequester, v LinkVerifier, m *metrics.Metrics, log *zap.Logger) *Handler {
	return &Handler{requester: r, verifier: v, metrics: m, log: log}
}

func (h *Handler) Request(w http.ResponseWriter, r *http.Request) {
	var req requestMagicLinkRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	if err := h.requester.RequestMagicLink(r.Context(), req.Email); err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &messageResponse{
		Message: "if the email exists, a magic link has been sent",
	})
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	var req verifyMagicLinkRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	pair, err := h.verifier.VerifyMagicLink(r.Context(), req.Token)
	if err != nil {
		h.metrics.AuthLoginTotal.WithLabelValues("magic_link", "failure").Inc()
		h.handleError(w, r, err)
		return
	}

	h.metrics.AuthLoginTotal.WithLabelValues("magic_link", "success").Inc()

	httputil.RespondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrMagicLinkNotFound):
		httputil.RespondError(w, http.StatusUnauthorized,
			"invalid or expired magic link", "INVALID_MAGIC_LINK")
	default:
		h.log.Error("magic link handler error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError,
			"internal server error", "INTERNAL_ERROR")
	}
}
