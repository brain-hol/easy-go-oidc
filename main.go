package main

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
)

type config struct {
	Addr string `env:"ADDR"`
	Port string `env:"PORT"`

	Issuer       string `env:"ISSUER"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	RedirectURL  string `env:"REDIRECT_URL"`
	Scopes       string `env:"SCOPES" default:"profile,openid"`
}

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	log := slog.Default()

	var cfg config
	if err := configFromEnv(&cfg, envPrefix("GOIDC_")); err != nil {
		log.Error("failed to load all config options", slog.Any("error", err))
		os.Exit(1)
	}
	log.Debug("loaded config", "cfg", cfg)

	provider, err := oidc.NewProvider(context.TODO(), cfg.Issuer)
	if err != nil {
		log.Error("failed to initialize provider", slog.Any("error", err))
		os.Exit(1)
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(cfg.Scopes, ","),
	}

	log.Info("", "authCodeURL", oauth2Config.AuthCodeURL("asdf"))
}
