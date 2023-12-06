package authenticateflow

import (
	"context"
)

// AuthEventKind is the type of an authentication event
type AuthEventKind string

const (
	// AuthEventSignInRequest is an authentication event for a sign in request before IdP redirect
	AuthEventSignInRequest AuthEventKind = "sign_in_request"
	// AuthEventSignInComplete is an authentication event for a sign in request after IdP redirect
	AuthEventSignInComplete AuthEventKind = "sign_in_complete"
)

// AuthEvent is a log event for an authentication event
type AuthEvent struct {
	// Event is the type of authentication event
	Event AuthEventKind
	// IP is the IP address of the client
	IP string
	// Version is the version of the Pomerium client
	Version string
	// RequestUUID is the UUID of the request
	RequestUUID string
	// PubKey is the public key of the client
	PubKey string
	// UID is the IdP user ID of the user
	UID *string
	// Email is the email of the user
	Email *string
	// Domain is the domain of the request (for sign in complete events)
	Domain *string
}

// AuthEventFn is a function that handles an authentication event
type AuthEventFn func(context.Context, AuthEvent)
