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
		s.log.Error("Failed to generate state", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		s.log.Error("Failed to marshal state JSON", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    base64.URLEncoding.EncodeToString(stateJSON),
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		Expires: time.Now().Add(3 * time.Minute),
	})

	http.Redirect(w, r, s.oauth2.AuthCodeURL(state.Nonce), http.StatusFound)
}

func (s *AuthService) handleCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		// Secure:   true, // Adjust according to your environment
	})
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		s.log.Error("Missing state cookie", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	stateEncoded := stateCookie.Value
	stateJSON, err := base64.URLEncoding.DecodeString(stateEncoded)
	if err != nil {
		s.log.Error("State cookie was not properly base64 URL encoded", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var state stateData
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		s.log.Error("Failed to unmarshall state data JSON", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	returnedState := r.URL.Query().Get("state")
	if returnedState == "" {
		s.log.Error("No state param was returned from the auth server", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if returnedState != state.Nonce {
		s.log.Error("State did not match", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	errorType := r.URL.Query().Get("error")
	if errorType != "" {
		errorDescription := r.URL.Query().Get("error_description")
		errorUri := r.URL.Query().Get("error_uri")
		s.log.Error("Errors returned from auth server", "type", errorType, "description", errorDescription, "uri", errorUri)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		s.log.Error("No code was returned from auth server", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oauth2.Exchange(r.Context(), authCode)
	if err != nil {
		s.log.Error("Error exchanging code for auth token", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.log.Error("No ID Token was returned with access token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	verifier := s.oidc.Verifier(&oidc.Config{
		ClientID: s.oauth2.ClientID,
	})

	_, err = verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.log.Error("Failed to verify ID token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	session, ok := r.Context().Value(sessionCtxKey).(*session)
	if session == nil || !ok {
		s.log.Error("No session found", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	session.Auth = oauth2Token
	
	http.Redirect(w, r, state.ReturnURL, http.StatusFound)
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

func createStateData(returnURL string) (*stateData, error) {
	nonce, err := generateNonce(32)
	if err != nil {
		return nil, err
	}

	state := &stateData{
		Nonce:     nonce,
		ReturnURL: returnURL,
	}
	return state, nil
}
