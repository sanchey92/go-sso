package model

type AuthorizationCode struct {
	ClientID            string `json:"client_id"`
	UserID              string `json:"user_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}
