package handler

import (
	"context"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
)

func (h *Handler) BatchValidateTokens(
	ctx context.Context,
	req *ssov1.BatchValidateTokensRequest,
) (*ssov1.BatchValidateTokensResponse, error) {
	tokens := req.GetTokens()
	if len(tokens) == 0 {
		return &ssov1.BatchValidateTokensResponse{}, nil
	}

	results := make([]*ssov1.BatchValidateResult, len(tokens))

	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, token := range tokens {
		results[i] = &ssov1.BatchValidateResult{Token: token}

		g.Go(func() error {
			claims, err := h.introspector.ValidateToken(token)
			if err == nil {
				results[i].Valid = true
				results[i].UserId = claims.Subject
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, status.Error(codes.Internal, "internal error") //nolint:wrapcheck // gRPC status error
	}

	return &ssov1.BatchValidateTokensResponse{Results: results}, nil
}
