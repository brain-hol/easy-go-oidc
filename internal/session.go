package internal

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
)

type contextKey string

const sessionCtxKey = contextKey("session")

type session struct {
	Auth *oauth2.Token
	IDToken *oidc.IDToken
}

type SessionManager interface {
	CreateSession() (string, *session)
	GetSession(string) (*session, bool)
	SaveSession(*session)
	DeleteSession(string)
}

type MemorySessionManager struct {
	sessions map[string]*session
	mu       sync.Mutex
}

func NewMemorySessionManager() *MemorySessionManager {
	return &MemorySessionManager{
		sessions: make(map[string]*session),
		mu:       sync.Mutex{},
	}
}

func (sm *MemorySessionManager) CreateSession() (string, *session) {
	sessionID := ksuid.New().String()
	session := &session{
		Auth: nil,
	}
	sm.mu.Lock()
	sm.sessions[sessionID] = session
	sm.mu.Unlock()

	return sessionID, session
}

func (sm *MemorySessionManager) GetSession(sessionID string) (*session, bool) {
	sm.mu.Lock()
	session, exists := sm.sessions[sessionID]
	sm.mu.Unlock()
	return session, exists
}

func (sm *MemorySessionManager) DeleteSession(sessionID string) {
	sm.mu.Lock()
	delete(sm.sessions, sessionID)
	sm.mu.Unlock()
}

func (sm *MemorySessionManager) SaveSession(s *session) {}

func SessionMiddleware(log *slog.Logger, sm SessionManager) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			var id string
			var sess *session
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				id, sess = sm.CreateSession()
				http.SetCookie(w, &http.Cookie{
					Name:    "session_id",
					Value:   id,
					Expires: time.Now().Add(24 * time.Hour),
				})
			} else {
				sess, _ = sm.GetSession(cookie.Value)
				if sess == nil {
					id, sess = sm.CreateSession()
					http.SetCookie(w, &http.Cookie{
						Name:    "session_id",
						Value:   id,
						Expires: time.Now().Add(24 * time.Hour),
					})
				}
			}
			ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
			sm.SaveSession(sess)
		}
		return http.HandlerFunc(fn)
	}
}
