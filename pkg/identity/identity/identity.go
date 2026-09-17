// Package identity is a package to avoid a dependency cycle.
package identity

// State is the state for authentication.
type State interface {
	SetRawIDToken(rawIDToken string)
}

type ReAuthenticationCapability = int

const (
	ReAuthenticationNone ReAuthenticationCapability = iota
	ReAuthenticationDisabled
	ReAuthenticationEnabled
)
