package internal

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/brain-hol/easy-go-oidc/internal/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(log *slog.Logger, auth *AuthService, sm SessionManager) *chi.Mux {
	r := chi.NewRouter()

	r.Use(SessionMiddleware(log, sm))
	r.Use(middleware.Heartbeat("/ping"))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := r.Context().Value(sessionCtxKey).(*session)
		if sess == nil || !ok {
			log.Error("No session found")
			httpx.InternalServerError(w)
			return
		}

		auth := sess.Auth
		if auth == nil {
			w.Write([]byte("Please login"))
			return
		}

		jsonStr, err := json.MarshalIndent(auth, "", "    ")
		if err != nil {
			log.Error("Failed to marshal auth JSON", slog.Any("error", err))
			httpx.InternalServerError(w)
			return
		}
		w.Write(jsonStr)

		idToken := sess.IDToken
		if idToken == nil {
			w.Write([]byte("Please login"))
			return
		}

		jsonStr, err = json.MarshalIndent(idToken, "", "    ")
		if err != nil {
			log.Error("Failed to marshal idToken JSON", slog.Any("error", err))
			httpx.InternalServerError(w)
			return
		}
		w.Write(jsonStr)
	})
	r.Get("/login", auth.handleLogin)
	r.Get("/callback", auth.handleCallback)
	return r
}
