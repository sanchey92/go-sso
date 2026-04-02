package discovery

import (
	"encoding/json"
	"net/http"
)

type Config struct {
	Issuer  string
	BaseURL string
}

type discoveryResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
}

type Handler struct {
	response []byte // pre-serialized JSON (immutable)
}

func NewHandler(cfg *Config) *Handler {
	resp := discoveryResponse{
		Issuer:                            cfg.Issuer,
		AuthorizationEndpoint:             cfg.BaseURL + "/api/v1/oauth/authorize",
		TokenEndpoint:                     cfg.BaseURL + "/api/v1/oauth/token",
		RevocationEndpoint:                cfg.BaseURL + "/api/v1/oauth/revoke",
		JwksURI:                           cfg.BaseURL + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"EdDSA"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethods:     []string{"none"},
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		UserinfoEndpoint:                  cfg.BaseURL + "/api/v1/oauth/userinfo",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		panic("failed to marshal discovery response: " + err.Error())
	}

	return &Handler{response: data}
}

func (h *Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.response) //nolint:gosec // error writing response body is unrecoverable
}
