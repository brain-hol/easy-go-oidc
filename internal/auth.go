package internal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type AuthService struct {
	log    *slog.Logger
	oauth2 *oauth2.Config
	oidc   *oidc.Provider
}

func NewAuthService(log *slog.Logger, oauth2 *oauth2.Config, oidc *oidc.Provider) *AuthService {
	return &AuthService{
		log:    log,
		oauth2: oauth2,
		oidc:   oidc,
	}
}

func (s *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return_url")
	returnURL, err := url.QueryUnescape(returnURL)
	if returnURL == "" || err != nil {
		returnURL = "/"
	}

	state, err := createStateData(returnURL)
	if err != nil {
		s.log.Error("Failed to generate state parameter", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		Expires: time.Now().Add(3 * time.Minute),
	})

	http.Redirect(w, r, s.oauth2.AuthCodeURL(state), http.StatusFound)
}

type stateData struct {
	Nonce     string `json:"nonce"`
	ReturnURL string `json:"return_url"`
}

func generateNonce(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func createStateData(returnURL string) (string, error) {
	nonce, err := generateNonce(32)
	if err != nil {
		return "", err
	}

	state := stateData{
		Nonce:     nonce,
		ReturnURL: returnURL,
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(stateJSON), nil
}
