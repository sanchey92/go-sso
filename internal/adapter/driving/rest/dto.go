package rest

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type revokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type registerResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type messageResponse struct {
	Message string `json:"message"`
}
