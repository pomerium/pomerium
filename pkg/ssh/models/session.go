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

func (x Session) Key() string {
	return x.SessionID
}

func (x *Session) Format() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Client IP:  %s\n", x.ClientIP)
	fmt.Fprintf(&b, "Public Key: %x\n", x.PublicKeyFingerprint)
	fmt.Fprintf(&b, "User ID:    %s\n", x.UserID)
	fmt.Fprintf(&b, "Session ID: %s\n", x.SessionID)
	fmt.Fprintf(&b, "Expires at: %s (in %s)\n",
		x.ExpiresAt.String(),
		time.Until(x.ExpiresAt).Round(time.Second))
	fmt.Fprintf(&b, "Claims:\n")
	keys := make([]string, 0, len(x.Claims))
	for key := range x.Claims {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s: ", key)
		vs := x.Claims[key]
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
