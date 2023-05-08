package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"

	"auth0-example-go/internal/app"
	"auth0-example-go/internal/config"
	"auth0-example-go/internal/handlers"
	"auth0-example-go/internal/middleware"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if err = config.New("demo"); err != nil {
		log.Fatal(err)
	}

	a, err := app.New()
	if err != nil {
		log.Fatal(err)
	}

	a.Server.GET("/test", handlers.TestHandler, middleware.ValidateJWT())

	addr := fmt.Sprintf(":%d", viper.GetInt("PORT"))

	if err := a.Server.Start(addr); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
