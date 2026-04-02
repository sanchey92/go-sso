package handler

import (
	"context"
	"encoding/json"
	"errors"

	"go.uber.org/zap"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
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
	cacheKey := "introspect:" + crypto.HashToken(req.GetToken())

	if resp, ok := h.getCachedIntrospection(ctx, cacheKey); ok {
		return resp, nil
	}

	claims, err := h.introspector.ValidateToken(req.GetToken())
	if err != nil {
		inactive := &cachedIntrospection{Active: false}
		h.cacheIntrospection(ctx, cacheKey, inactive)
		return cacheToProto(inactive), nil //nolint:nilerr // invalid token returns inactive response, not error
	}

	cached := claimsToCache(claims)
	h.cacheIntrospection(ctx, cacheKey, cached)

	return cacheToProto(cached), nil
}

func (h *Handler) getCachedIntrospection(ctx context.Context, key string) (*ssov1.IntrospectTokenResponse, bool) {
	data, err := h.cache.Get(ctx, key)
	if err != nil {
		if !errors.Is(err, domainerrors.ErrKeyNotFound) {
			h.log.Warn("introspection cache get error", zap.Error(err))
		}
		return nil, false
	}

	var cached cachedIntrospection
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		h.log.Warn("introspection cache unmarshal error", zap.Error(err))
		return nil, false
	}

	return cacheToProto(&cached), true
}

func (h *Handler) cacheIntrospection(ctx context.Context, key string, val *cachedIntrospection) {
	data, err := json.Marshal(val)
	if err != nil {
		h.log.Warn("introspection cache marshal error", zap.Error(err))
		return
	}

	if err := h.cache.Set(ctx, key, string(data), h.cacheTTL); err != nil {
		h.log.Warn("introspection cache set error", zap.Error(err))
	}
}
