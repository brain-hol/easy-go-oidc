package internal

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/brain-hol/easy-go-oidc/internal/httpx"
)

type HomeService struct {
	log *slog.Logger
}

func NewHomeService(log *slog.Logger) *HomeService {
	return &HomeService{
		log: log,
	}
}

func (s *HomeService) handleHome(w http.ResponseWriter, r *http.Request) {
	sess, ok := r.Context().Value(sessionCtxKey).(*session)
	if sess == nil || !ok {
		s.log.Error("No session found")
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
		s.log.Error("Failed to marshal auth JSON", slog.Any("error", err))
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
		s.log.Error("Failed to marshal idToken JSON", slog.Any("error", err))
		httpx.InternalServerError(w)
		return
	}
	w.Write(jsonStr)

	var claims map[string]json.RawMessage
	if err = idToken.Claims(&claims); err != nil {
		s.log.Error("Failed to unmarshal claims", slog.Any("error", err))
		httpx.InternalServerError(w)
		return
	}
	claimsBytes, err := json.MarshalIndent(claims, "", "    ")
	if err != nil {
		s.log.Error("Failed to marshal claims", slog.Any("error", err))
		httpx.InternalServerError(w)
		return
	}
	w.Write(claimsBytes)
}
