package model

import (
	"time"
)

type Session struct {
	UserID               string
	SessionID            string
	Claims               map[string][]any
	PublicKeyFingerprint []byte
	ClientIP             string
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

func (c Session) Key() string {
	return c.SessionID
}
