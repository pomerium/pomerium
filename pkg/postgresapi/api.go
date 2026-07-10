// Package postgresapi defines the public HTTP contract used to create native
// PostgreSQL session bindings.
package postgresapi

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/pomerium/pomerium/internal/postgresidentity"
)

const (
	// SessionBindingsPath is the authenticated endpoint used to bind a
	// PostgreSQL client certificate to a Pomerium session.
	SessionBindingsPath = "/.pomerium/api/v1/postgres/session-bindings"
	// LoginRouteQuery selects the native PostgreSQL route whose identity
	// provider should be used by the programmatic login flow.
	LoginRouteQuery = "pomerium_postgres_route"
	// MaxCreateSessionBindingRequestBytes bounds the unauthenticated HTTP body
	// accepted before the session handle is validated.
	MaxCreateSessionBindingRequestBytes = 16 * 1024

	sessionBindingProofDomain = "pomerium.com/native-postgres/session-binding/v1\x00"
)

// CreateSessionBindingRequest requests a short-lived binding for a constrained
// self-signed client certificate.
type CreateSessionBindingRequest struct {
	RouteHost      string `json:"route_host"`
	CertificatePEM string `json:"certificate_pem"`
	ProofSignature string `json:"proof_signature"`
}

// CreateSessionBindingResponse describes the binding created by Pomerium.
type CreateSessionBindingResponse struct {
	BindingID string    `json:"binding_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionBindingProofMessage returns the canonical message signed by the
// private key corresponding to CertificatePEM when creating a PostgreSQL
// session binding. The session handle is the raw signed token after the
// "Bearer Pomerium-" prefix has been removed.
func SessionBindingProofMessage(routeHostname, rawSessionHandle string, certificateDER []byte) ([]byte, error) {
	routeHostname = postgresidentity.CanonicalHostname(routeHostname)
	if routeHostname == "" || rawSessionHandle == "" || len(certificateDER) == 0 {
		return nil, errors.New("postgres session binding proof inputs are incomplete")
	}
	if len(routeHostname) > math.MaxUint32 {
		return nil, errors.New("postgres route hostname is too long")
	}

	handleHash := sha256.Sum256([]byte(rawSessionHandle))
	certificateHash := sha256.Sum256(certificateDER)
	message := make([]byte, 0, len(sessionBindingProofDomain)+4+len(routeHostname)+len(handleHash)+len(certificateHash))
	message = append(message, sessionBindingProofDomain...)
	message = binary.BigEndian.AppendUint32(message, uint32(len(routeHostname)))
	message = append(message, routeHostname...)
	message = append(message, handleHash[:]...)
	message = append(message, certificateHash[:]...)
	return message, nil
}
