package internal

import (
	"sync"

	"golang.org/x/oauth2"
)

type contextKey string

const sessionCtxKey = contextKey("session")

type session struct {
	ID   string
	Auth *oauth2.Token
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

func (sm *MemorySessionManager) CreateSession
