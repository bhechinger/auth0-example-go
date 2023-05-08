package middleware

import (
	"context"
	"net/http"
	"net/url"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"auth0-example-go/internal/helpers"
)

const (
	missingJWTErrorMessage     = "Requires authentication"
	invalidJWTErrorMessage     = "Bad credentials"
	internalServerErrorMessage = "Internal Server Error"
	//permissionDeniedErrorMessage = "Permission denied"
)

type (
	// ValidateJWTConfig defines the config for ValidateJWT middleware.
	ValidateJWTConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper
	}

	CustomClaims struct {
		Permissions []string `json:"permissions"`
	}

	ErrorMessage struct {
		Message string `json:"message"`
	}
)

var (
	// DefaultValidateJWTConfig is the default Validator middleware config.
	DefaultValidateJWTConfig = ValidateJWTConfig{
		Skipper: middleware.DefaultSkipper,
	}
)

func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

func ValidateJWT() echo.MiddlewareFunc {
	return ValidateJWTWithConfig(DefaultValidateJWTConfig)
}

func ValidateJWTWithConfig(config ValidateJWTConfig) echo.MiddlewareFunc {
	audience := viper.GetString("auth0_audience")
	domain := viper.GetString("auth0_domain")

	log.Info("Using audience: ", audience)
	log.Info("Using domain: ", domain)

	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultValidateJWTConfig.Skipper
	}

	return echo.WrapMiddleware(doValidateJWT(audience, domain))
}

func doValidateJWT(audience, domain string) func(next http.Handler) http.Handler {
	issuerURL, err := url.Parse("https://" + domain + "/")
	if err != nil {
		log.Errorf("Failed to parse the issuer url: %s", err)
	}

	log.Infof("issuerURL: %s", issuerURL)

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{audience},
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &CustomClaims{}
			},
		),
	)
	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Infof("Encountered error while validating JWT: %v", err)
		if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
			errorMessage := ErrorMessage{Message: missingJWTErrorMessage}
			herr := helpers.WriteJSON(w, http.StatusUnauthorized, errorMessage)
			if herr != nil {
				log.Errorf("Error writing JSON output: %s", herr)
			}

			return
		}

		if errors.Is(err, jwtmiddleware.ErrJWTInvalid) {
			errorMessage := ErrorMessage{Message: invalidJWTErrorMessage}
			herr := helpers.WriteJSON(w, http.StatusUnauthorized, errorMessage)
			if herr != nil {
				log.Errorf("Error writing JSON output: %s", herr)
			}

			return
		}
		ServerError(w, err)
	}

	mw := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
	)

	return func(next http.Handler) http.Handler {
		return mw.CheckJWT(next)
	}
}

func ServerError(rw http.ResponseWriter, err error) {
	errorMessage := ErrorMessage{Message: internalServerErrorMessage}
	herr := helpers.WriteJSON(rw, http.StatusInternalServerError, errorMessage)
	if herr != nil {
		log.Errorf("Error writing JSON output: %s", herr)
	}

	log.Errorf("Internal error server: %s", err)
}
