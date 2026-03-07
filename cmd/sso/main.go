package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/sanchey92/sso/internal/app"
	"github.com/sanchey92/sso/internal/config"
)

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("failed to load .env file: %v", err)
	}

	cfg := config.MustLoad(os.Getenv("CONFIG_PATH"))

	a, err := app.NewApp(cfg)
	if err != nil {
		log.Fatalf("failed to init usecase: %v", err)
	}

	a.Run()
}
