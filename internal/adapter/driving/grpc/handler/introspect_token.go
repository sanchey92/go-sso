package handler

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/pkg/crypto"
)

type cachedIntrospection struct {
	Active    bool   `json:"active"`
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	Audience  string `json:"audience,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	IssuedAt  int64  `json:"issued_at,omitempty"`
}

func (h *Handler) IntrospectToken(
	ctx context.Context,
	req *ssov1.IntrospectTokenRequest,
) (*ssov1.IntrospectTokenResponse, error) {
	cacheKey := "introspect" + crypto.HashToken(req.GetToken())

	if resp, ok := h.getCachedIntrospection(ctx, cacheKey); ok {
		return resp, nil
	}

	claims, err := h.introspector.ValidateToken(req.GetToken())
	if err != nil {
		resp := &ssov1.IntrospectTokenResponse{Active: false}
		h.cacheIntrospection(ctx, cacheKey, &cachedIntrospection{Active: false})
		return resp, nil
	}

	cached := &cachedIntrospection{
		Active:    true,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  claims.IssuedAt.Unix(),
	}

	h.cacheIntrospection(ctx, cacheKey, cached)

	return &ssov1.IntrospectTokenResponse{
		Active:    true,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: timestamppb.New(claims.ExpiresAt),
		IssuedAt:  timestamppb.New(claims.IssuedAt),
	}, nil

}

func (h *Handler) getCachedIntrospection(ctx context.Context, key string) (*ssov1.IntrospectTokenResponse, bool) {
	return nil, false
}

func (h *Handler) cacheIntrospection(ctx context.Context, key string, val *cachedIntrospection) {
}
