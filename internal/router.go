package internal

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(log *slog.Logger, auth *AuthService, sm SessionManager) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Heartbeat("/ping"))
	r.Use(SessionMiddleware(log, sm))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := r.Context().Value(sessionCtxKey).(*session)
		if sess == nil || !ok {
			log.Error("No session found")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		auth := sess.Auth
		if auth == nil {
			w.Write([]byte("Please login"))
			return
		}

		jsonStr, err := json.Marshal(auth)
		if err != nil {
			log.Error("Failed to marshal auth JSON", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Write(jsonStr)

		idToken := sess.IDToken
		if idToken == nil {
			w.Write([]byte("Please login"))
			return
		}

		jsonStr, err = json.Marshal(idToken)
		if err != nil {
			log.Error("Failed to marshal idToken JSON", slog.Any("error", err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Write(jsonStr)
	})
	r.Get("/login", auth.handleLogin)
	r.Get("/callback", auth.handleCallback)
	return r
}
