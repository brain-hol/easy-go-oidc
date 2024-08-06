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
		s.log.Error("Failed to generate auth state before authorize request", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		s.log.Error("Failed to marshal auth state to JSON", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    base64.URLEncoding.EncodeToString(stateJSON),
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		Expires: time.Now().Add(3 * time.Minute),
	})

	http.Redirect(w, r, s.oauth2.AuthCodeURL(state.Nonce), http.StatusFound)
}

func (s *AuthService) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Remove auth state cookie regardless of result of authorize response
	httpx.UnsetCookie(w, oauthStateCookie)

	// Check for errors from auth server
	errorType := r.URL.Query().Get("error")
	if errorType != "" {
		errorDescription := r.URL.Query().Get("error_description")
		errorUri := r.URL.Query().Get("error_uri")
		s.log.Error("Error returned from authorize endpoint", slog.String("type", errorType), slog.String("description", errorDescription), slog.String("uri", errorUri))
		httpx.BadRequest(w)
		return
	}

	// Get the state from the request's cookie
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil {
		s.log.Error("Missing auth state cookie", slog.Any("error", err))
		httpx.BadRequest(w)
		return
	}
	stateEncoded := stateCookie.Value
	stateJSON, err := base64.URLEncoding.DecodeString(stateEncoded)
	if err != nil {
		s.log.Error("Auth state cookie was not properly base64 URL encoded", slog.Any("error", err))
		httpx.BadRequest(w)
		return
	}
	var state stateData
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		s.log.Error("Failed to unmarshall auth state data JSON", slog.Any("error", err))
		httpx.BadRequest(w)
		return
	}

	// Get the state returned from the authorize endpoint
	returnedState := r.URL.Query().Get("state")
	if returnedState == "" {
		s.log.Error("No state param was returned in authorize response")
		httpx.BadRequest(w)
		return
	}

	// Ensure the returned state and the cookie state.Nonce are the same
	if returnedState != state.Nonce {
		s.log.Error("Authorize response state and cookie state did not match")
		httpx.BadRequest(w)
		return
	}

	// Get code from auth server
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		s.log.Error("No code was returned from auth server")
		httpx.BadRequest(w)
		return
	}

	oauth2Token, err := s.oauth2.Exchange(r.Context(), authCode)
	if err != nil {
		s.log.Error("Error exchanging code for auth token", slog.Any("error", err))
		httpx.BadRequest(w)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.log.Error("No id token was returned with access token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	verifier := s.oidc.Verifier(&oidc.Config{ClientID: s.oauth2.ClientID})

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.log.Error("Failed to verify id token", slog.Any("error", err))
		httpx.BadRequest(w)
		return
	}

	session, ok := r.Context().Value(sessionCtxKey).(*session)
	if session == nil || !ok {
		s.log.Error("No session found")
		httpx.BadRequest(w)
		return
	}
	session.Auth = oauth2Token
	session.IDToken = idToken

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
