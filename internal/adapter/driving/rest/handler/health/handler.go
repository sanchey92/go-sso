package health

import (
	"context"
	"net/http"
	"time"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
)

const readinessTimeout = time.Second

type PingChecker interface {
	Ping(ctx context.Context) error
}

type Handler struct {
	postgres PingChecker
	redis    PingChecker
}

func NewHandler(postgres, redis PingChecker) *Handler {
	return &Handler{postgres: postgres, redis: redis}
}

func (h *Handler) Liveness(w http.ResponseWriter, _ *http.Request) {
	httputil.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	checks := make(map[string]string, 2)
	ready := true

	if err := h.postgres.Ping(ctx); err != nil {
		checks["postgres"] = "error: " + err.Error()
		ready = false
	} else {
		checks["postgres"] = "ok"
	}

	if err := h.redis.Ping(ctx); err != nil {
		checks["redis"] = "error: " + err.Error()
		ready = false
	} else {
		checks["redis"] = "ok"
	}

	status := http.StatusOK
	statusText := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		statusText = "not_ready"
	}

	httputil.RespondJSON(w, status, map[string]any{
		"status": statusText,
		"checks": checks,
	})
}
