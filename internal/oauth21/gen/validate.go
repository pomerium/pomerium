package gen

import (
	"fmt"
	"time"
)

func (t *UpstreamMCPToken) Validate(sessionID string) error {
	if t == nil {
		return fmt.Errorf("no token")
	}
	if t.ExpiresAt != nil && t.ExpiresAt.AsTime().Before(time.Now()) {
		return fmt.Errorf("expired token")
	}
	if t.IsPomeriumIssuedToken() && t.GetPomeriumAuthorizationSessionId() != sessionID {
		return fmt.Errorf("token no longer valid for session")
	}

	return nil
}

func (t *UpstreamMCPToken) IsPomeriumIssuedToken() bool {
	return t != nil && t.PomeriumAuthorizationSessionId != nil
}
