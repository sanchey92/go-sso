package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const maxBodySize = 1 << 20

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func respondError(w http.ResponseWriter, status int, msg, code string) {
	respondJSON(w, status, ErrorResponse{Error: msg, Code: code})
}
