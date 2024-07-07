package internal

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(auth *AuthService) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Heartbeat("/ping"))
	r.Get("/login", auth.handleLogin)
	return r
}
