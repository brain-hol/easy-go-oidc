package main

import (
	"context"
	"crypto/tls"
	_ "embed"
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
	Scopes       string `env:"SCOPES" default:"profile,openid"`
}

//go:embed certs/server.cert.pem
var certBytes []byte

//go:embed certs/server.key.pem
var keyBytes []byte

func main() {
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
		RedirectURL:  fmt.Sprintf("https://%s:%s/callback", cfg.Addr, cfg.Port),
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(cfg.Scopes, ","),
	}
	authService := internal.NewAuthService(log, &oauth2Config, provider)

	sm := internal.NewMemorySessionManager()
	home := internal.NewHomeService(log)

	r := internal.NewRouter(log, authService, sm, home)

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		log.Error("Failed to create server key pair", slog.Any("error", err))
		os.Exit(1)
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server := http.Server{
		Addr:      fmt.Sprintf("%s:%s", cfg.Addr, cfg.Port),
		TLSConfig: &tlsConfig,
		Handler:   r,
	}
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	log.Debug("Server listening", "addr", cfg.Addr, "port", cfg.Port)
}
