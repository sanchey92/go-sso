package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func (h *Handler) GetUser(ctx context.Context, req *ssov1.GetUserRequest) (*ssov1.GetUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	user, err := h.users.GetByID(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return userToProto(user), nil
}
