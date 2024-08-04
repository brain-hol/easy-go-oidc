package internal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/brain-hol/easy-go-oidc/internal/httpx"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	oauthStateCookie = "auth_state"
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
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		Expires: time.Now().Add(3 * time.Minute),
	})

	http.Redirect(w, r, s.oauth2.AuthCodeURL(state), http.StatusFound)
}

func (s *AuthService) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Remove auth state cookie regardless of result of callback
	httpx.UnsetCookie(w, oauthStateCookie)

	// Check for errors from auth server
	errorType := r.URL.Query().Get("error")
	if errorType != "" {
		errorDescription := r.URL.Query().Get("error_description")
		errorUri := r.URL.Query().Get("error_uri")
		s.log.Error("Error returned from authorize endpoint", slog.String("type", errorType), slog.String("description", errorDescription), slog.String("uri", errorUri))
		httpx.BadRequest(w, r)
		return
	}

	// Get the state from the request's cookie
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil {
		s.log.Error("Missing state cookie", slog.Any("error", err))
		httpx.BadRequest(w, r)
		return
	}
	stateEncoded := stateCookie.Value

	// Get the state returned from the authorize endpoint
	returnedState := r.URL.Query().Get("state")
	if returnedState == "" {
		s.log.Error("No state param was returned from the auth server")
		httpx.BadRequest(w, r)
		return
	}

	// Ensure the returned state and the cookie state are the same
	if returnedState != stateEncoded {
		s.log.Error("State returned from provider did not match state from cookie")
		httpx.BadRequest(w, r)
		return
	}

	// Get code from auth server
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		s.log.Error("No auth code returned from auth server")
		httpx.BadRequest(w, r)
		return
	}

	token, err := s.oauth2.Exchange(r.Context(), authCode)
	if err != nil {
		s.log.Error("Failed to exchange auth code for access token", slog.Any("error", err))
		httpx.BadRequest(w, r)
		return
	}

	atBytes, err := json.MarshalIndent(token, "", "    ")
	if err != nil {
		s.log.Error("Failed to marshal access token", slog.Any("error", err))
		httpx.InternalServerError(w, r)
		return
	}
	w.Write(atBytes)
	w.Write([]byte("\n\n\n"))

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.log.Error("No id token was returned with access token")
		httpx.BadRequest(w, r)
		return
	}

	verifier := s.oidc.Verifier(&oidc.Config{ClientID: s.oauth2.ClientID})

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.log.Error("Failed to verify the id token", slog.Any("error", err))
		httpx.BadRequest(w, r)
		return
	}

	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		s.log.Error("Failed to parse claims from id token", slog.Any("error", err))
		httpx.BadRequest(w, r)
		return
	}

	// Temp, delete this later
	claimsBytes, err := json.MarshalIndent(claims, "", "    ")
	if err != nil {
		s.log.Error("Failed to marshal claims", slog.Any("error", err))
		httpx.InternalServerError(w, r)
		return
	}
	w.Write(claimsBytes)

	// stateJSON, err := base64.URLEncoding.DecodeString(stateEncoded)
	// if err != nil {
	// 	s.log.Error("State cookie was not properly base64 encoded", slog.Any("error", err))
	// 	httpx.BadRequest(w, r)
	// 	return
	// }

	// var state stateData
	// if err := json.Unmarshal(stateJSON, &state); err != nil {
	// 	s.log.Error("Failed to parse state data as JSON", slog.Any("error", err))
	// 	httpx.BadRequest(w, r)
	// 	return
	// }
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
