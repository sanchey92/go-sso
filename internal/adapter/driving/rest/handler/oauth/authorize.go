package oauth

import (
	"errors"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type authorizeRequest struct {
	clientID            string
	redirectURI         string
	responseType        string
	scope               string
	state               string
	codeChallenge       string
	codeChallengeMethod string
	userID              string
}

type authzValidationError struct {
	httpError bool // true -> respondError (JSON), false -> redirectWithError
	code      string
	desc      string
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	req := parseAuthorizeRequest(r)

	if vErr := req.validate(); vErr != nil {
		if vErr.httpError {
			httputil.RespondError(w, http.StatusBadRequest, vErr.desc, vErr.code)
		} else {
			redirectWithError(w, r, req.redirectURI, vErr.code, vErr.desc, req.state)
		}
		return
	}

	params := &model.AuthorizationCode{
		ClientID:            req.clientID,
		UserID:              req.userID,
		RedirectURI:         req.redirectURI,
		Scope:               req.scope,
		CodeChallenge:       req.codeChallenge,
		CodeChallengeMethod: req.codeChallengeMethod,
	}

	code, err := h.svc.Authorize(r.Context(), params)
	if err != nil {
		h.handleAuthorizeError(w, r, err, req.redirectURI, req.state)
		return
	}

	redirectURL := buildRedirectURL(req.redirectURI, code, req.state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func parseAuthorizeRequest(r *http.Request) authorizeRequest {
	q := r.URL.Query()
	return authorizeRequest{
		clientID:            q.Get("client_id"),
		redirectURI:         q.Get("redirect_uri"),
		responseType:        q.Get("response_type"),
		scope:               q.Get("scope"),
		state:               q.Get("state"),
		codeChallenge:       q.Get("code_challenge"),
		codeChallengeMethod: q.Get("code_challenge_method"),
		userID:              q.Get("user_id"),
	}
}

func (req authorizeRequest) validate() *authzValidationError {
	// Pre-redirect: RFC 6749 §4.1.2.1 — НЕ редиректить
	if req.clientID == "" {
		return &authzValidationError{httpError: true, code: "INVALID_REQUEST", desc: "client_id is required"}
	}
	if req.redirectURI == "" {
		return &authzValidationError{httpError: true, code: "INVALID_REQUEST", desc: "redirect_uri is required"}
	}
	// Post-redirect
	if req.responseType != "code" {
		return &authzValidationError{code: "unsupported_response_type", desc: "response_type must be 'code'"}
	}
	if req.codeChallenge == "" {
		return &authzValidationError{code: "invalid_request", desc: "code_challenge is required"}
	}
	if req.codeChallengeMethod != "S256" {
		return &authzValidationError{code: "invalid_request", desc: "code_challenge_method must be S256"}
	}
	if req.userID == "" {
		return &authzValidationError{code: "invalid_request", desc: "user_id is required"}
	}
	return nil
}

func (h *Handler) handleAuthorizeError(w http.ResponseWriter, r *http.Request,
	err error, redirectURI, state string,
) {
	switch {
	case errors.Is(err, domainerrors.ErrOAuthClientNotFound):
		// RFC 6749 §4.1.2.1: НЕ редиректить при невалидном client_id
		httputil.RespondError(w, http.StatusBadRequest, "invalid client_id", "INVALID_CLIENT")
	case errors.Is(err, domainerrors.ErrInvalidRedirectURI):
		// RFC 6749 §4.1.2.1: НЕ редиректить при невалидном redirect_uri
		httputil.RespondError(w, http.StatusBadRequest, "invalid redirect_uri", "INVALID_REDIRECT_URI")
	default:
		h.log.Error("authorize error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		redirectWithError(w, r, redirectURI, "server_error", "internal server error", state)
	}
}

func redirectWithError(w http.ResponseWriter, r *http.Request,
	redirectURI, errorCode, errorDesc, state string,
) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid redirect_uri", "INVALID_REQUEST")
		return
	}
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func buildRedirectURL(redirectURI, code, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
