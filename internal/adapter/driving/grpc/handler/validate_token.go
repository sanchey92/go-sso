package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func (h *Handler) ValidateToken(
	ctx context.Context,
	req *ssov1.ValidateTokenRequest,
) (*ssov1.ValidateTokenResponse, error) {
	claims, err := h.introspector.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	user, err := h.users.GetByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			return nil, status.Error(codes.Unauthenticated, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return validateTokenToProto(user), nil
}
