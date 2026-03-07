package email

import (
	"context"

	"go.uber.org/zap"
)

type LogSender struct {
	log     *zap.Logger
	baseURL string
}

func NewLogSender(log *zap.Logger, baseURL string) *LogSender {
	return &LogSender{
		log:     log,
		baseURL: baseURL,
	}
}

func (s *LogSender) SendVerificationEmail(_ context.Context, toEmail, token string) error {
	s.log.Info("verification email",
		zap.String("to", toEmail),
		zap.String("verification_url", s.baseURL+"/api/v1/auth/email/verify?token="+token),
	)
	return nil
}
