package main

import (
	"log"

	"github.com/aussiebroadwan/bartab/internal/auth/app"
)

func main() {
	cfg := app.LoadConfig()

	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}

	if err := application.Run(); err != nil {
		log.Fatalf("application error: %v", err)
	}
}
