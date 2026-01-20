package models

import (
	"bytes"
	"fmt"
	"slices"
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

func (s *Session) Key() string {
	return s.SessionID
}

// EmailOrUserID returns the user's email address, or user ID if there is no
// email claim available.
func (s *Session) EmailOrUserID() string {
	if id := s.Claims["email"]; len(id) > 0 {
		return id[0].(string)
	}
	return s.UserID
}

func (s *Session) Format() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Client IP:  %s\n", s.ClientIP)
	fmt.Fprintf(&b, "Public Key: %x\n", s.PublicKeyFingerprint)
	fmt.Fprintf(&b, "User ID:    %s\n", s.UserID)
	fmt.Fprintf(&b, "Session ID: %s\n", s.SessionID)
	fmt.Fprintf(&b, "Expires at: %s (in %s)\n",
		s.ExpiresAt.String(),
		time.Until(s.ExpiresAt).Round(time.Second))
	fmt.Fprintf(&b, "Claims:\n")
	keys := make([]string, 0, len(s.Claims))
	for key := range s.Claims {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s: ", key)
		vs := s.Claims[key]
		if len(vs) != 1 {
			b.WriteRune('[')
		}
		if len(vs) == 1 {
			switch key {
			case "iat":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (%s ago)", t, time.Since(t).Round(time.Second))
			case "exp":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (in %s)", t, time.Until(t).Round(time.Second))
			default:
				fmt.Fprintf(&b, "%#v", vs[0])
			}
		} else if len(vs) > 1 {
			for i, v := range vs {
				fmt.Fprintf(&b, "%#v", v)
				if i < len(vs)-1 {
					b.WriteString(", ")
				}
			}
		}
		if len(vs) != 1 {
			b.WriteRune(']')
		}
		b.WriteRune('\n')
	}
	return b.String()
}
