package handlers

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

func TestHandler(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token) // by default token is stored under `user` key
	if !ok {
		return errors.New("JWT token missing or invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		return errors.New("failed to cast claims as jwt.MapClaims")
	}

	return c.JSON(http.StatusOK, claims)
}
