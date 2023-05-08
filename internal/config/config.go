package config

import (
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func New(envPrefix string) error {
	viper.SetEnvPrefix(envPrefix)
	err := viper.BindEnv("secret")
	if err != nil {
		return errors.Wrap(err, "failed to bind secret variable")
	}

	err = viper.BindEnv("port")
	if err != nil {
		return errors.Wrap(err, "failed to bind port variable")
	}

	err = viper.BindEnv("auth0_audience")
	if err != nil {
		return errors.Wrap(err, "failed to bind auth0_audience variable")
	}

	err = viper.BindEnv("auth0_domain")
	if err != nil {
		return errors.Wrap(err, "failed to bind auth0_domain variable")
	}

	err = viper.BindEnv("client_origin_url")
	if err != nil {
		return errors.Wrap(err, "failed to bind auth0_domain variable")
	}

	return nil
}
