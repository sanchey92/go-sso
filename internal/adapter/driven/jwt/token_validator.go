package jwt

type TokenValidator struct {
	svc *Service
}

func NewTokenValidator(svc *Service) *TokenValidator {
	return &TokenValidator{svc: svc}
}

func (v *TokenValidator) ValidateToken(token string) (string, error) {
	claims, err := v.svc.ValidateToken(token)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}
