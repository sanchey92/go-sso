package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/pkg/logger"
)

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("failed to load .env file: %v", err)
	}
	path := os.Getenv("CONFIG_PATH")
	cfg := config.MustLoad(path)

	l := logger.New(&logger.Config{
		Level:  cfg.Observability.Log.Level,
		Format: cfg.Observability.Log.Format,
	})

	l.Info("zap logger initialized")
}
