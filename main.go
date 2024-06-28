package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	_ "github.com/joho/godotenv/autoload"
)

const ENV_PREFIX = "GOIDC_"

func main() {
	addr := flag.String("addr", getEnv("ADDR", ""), "Address to listen for TCP connections on")
	port := flag.String("port", getEnv("PORT", "1200"), "Port to listen for TCP connections on")
	configURL := flag.String("config-url", getEnv("CONFIG_URL", ""), "URL to get OIDC configuration")

	flag.Parse()

	if *configURL == "" {
		slog.Default().Error("No configURL was provided")
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	oidcService := newOpenIDService(slog.Default(), *configURL)
	oidcHandler := newOpenIDHandler(slog.Default(), oidcService)
	r.Get("/config", oidcHandler.printConfig)

	http.ListenAndServe(fmt.Sprintf("%s:%s", *addr, *port), r)
}

func getEnv(key string, fallback string) string {
	if value, exists := os.LookupEnv(fmt.Sprintf(ENV_PREFIX + key)); exists {
		return value
	}
	return fallback
}
