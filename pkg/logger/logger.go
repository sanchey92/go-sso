package logger

import (
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Level  string
	Format string
}

func New(cfg *Config) *zap.Logger {
	logLevel := parseLevel(cfg.Level)
	encoder := buildEncoder(cfg.Format)

	core := zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), logLevel)

	logger := zap.New(
		core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	return logger
}

func parseLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "info":
		return zapcore.InfoLevel
	case "debug":
		return zapcore.DebugLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zap.InfoLevel
	}
}

func buildEncoder(format string) zapcore.Encoder {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     iso8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	switch strings.ToLower(format) {
	case "console":
		return zapcore.NewConsoleEncoder(encoderConfig)
	default:
		return zapcore.NewJSONEncoder(encoderConfig)
	}
}

func iso8601TimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.UTC().Format(time.RFC3339))
}
