package internal

import (
	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(log *slog.Logger, auth *AuthService, sm SessionManager, home *HomeService) *chi.Mux {
	r := chi.NewRouter()

	r.Use(SessionMiddleware(log, sm))
	r.Use(middleware.Heartbeat("/ping"))

	r.Get("/", home.handleHome)
	r.Get("/login", auth.handleLogin)
	r.Get("/callback", auth.handleCallback)
	return r
}
