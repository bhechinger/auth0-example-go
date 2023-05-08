package app

import (
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/cors"
	"github.com/spf13/viper"
)

type App struct {
	Server *echo.Echo
}

func New() (*App, error) {
	var app App

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: []string{viper.GetString("client_origin_url")},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         86400,
	})

	app.Server = echo.New()
	app.Server.Use(middleware.Logger())
	app.Server.Use(middleware.Recover())
	app.Server.Use(echo.WrapMiddleware(corsMiddleware.Handler))

	app.Server.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte(viper.GetString("secret")),
	}))

	return &app, nil

}
