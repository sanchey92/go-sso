package federation

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	query := r.URL.Query()

	if errCode := query.Get("error"); errCode != "" {
		desc := query.Get("error_description")
		h.log.Warn("provider returned error",
			zap.String("provider", provider),
			zap.String("error", errCode),
			zap.String("error_description", desc),
		)
		httputil.RespondError(w, http.StatusBadRequest, desc, errCode)
		return
	}

	code := query.Get("code")
	if code == "" {
		httputil.RespondError(w, http.StatusBadRequest, "code is required", "INVALID_REQUEST")
		return
	}

	state := query.Get("state")
	if state == "" {
		httputil.RespondError(w, http.StatusBadRequest, "state is required", "INVALID_REQUEST")
		return
	}

	pair, err := h.callback.HandleCallback(r.Context(), provider, code, state)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
		RefreshToken: pair.RefreshToken,
	})
}
