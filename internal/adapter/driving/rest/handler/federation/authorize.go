package federation

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	authURL, err := h.initiator.InitiateOAuth(r.Context(), provider)
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}
