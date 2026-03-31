package handler

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/internal/domain/model"
)

func claimsToCache(claims *model.TokenClaims) *cachedIntrospection {
	return &cachedIntrospection{
		Active:    true,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  claims.IssuedAt.Unix(),
	}
}

func cacheToProto(c *cachedIntrospection) *ssov1.IntrospectTokenResponse {
	resp := &ssov1.IntrospectTokenResponse{Active: c.Active}
	if c.Active {
		resp.Subject = c.Subject
		resp.Issuer = c.Issuer
		resp.Audience = c.Audience
		resp.ExpiresAt = timestamppb.New(time.Unix(c.ExpiresAt, 0))
		resp.IssuedAt = timestamppb.New(time.Unix(c.IssuedAt, 0))
	}
	return resp
}

func userToProto(user *model.User) *ssov1.ValidateTokenResponse {
	return &ssov1.ValidateTokenResponse{
		Valid:         true,
		UserId:        user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}
}
