package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/brain-hol/easy-go-oidc/internal"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	_ "github.com/joho/godotenv/autoload"
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
	// slog.SetLogLoggerLevel(slog.LevelDebug)
	// log := slog.Default()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	var cfg config
	if err := internal.ConfigFromEnv(&cfg, internal.EnvPrefix("GOIDC_")); err != nil {
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

	authService := internal.NewAuthService(log, &oauth2Config, provider)

	r := internal.NewRouter(authService)
	err = http.ListenAndServe(fmt.Sprintf("%s:%s", cfg.Addr, cfg.Port), r)
	if err != nil {
		log.Error("Failed to start server", slog.Any("error", err))
	}
}
