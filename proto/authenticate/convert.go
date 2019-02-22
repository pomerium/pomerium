package authenticate

import (
	fmt "fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/internal/sessions"
)

// SessionFromProto converts a converts a protocol buffer session into a pomerium session state.
func SessionFromProto(p *Session) (*sessions.SessionState, error) {
	if p == nil {
		return nil, fmt.Errorf("proto/authenticate: SessionFromProto session cannot be nil")
	}
	lifetimeDeadline, err := ptypes.Timestamp(p.LifetimeDeadline)
	if err != nil {
		return nil, fmt.Errorf("proto/authenticate: couldn't parse lifetime deadline %v", err)
	}
	refreshDeadline, err := ptypes.Timestamp(p.RefreshDeadline)
	if err != nil {
		return nil, fmt.Errorf("proto/authenticate: couldn't parse refresh deadline %v", err)
	}
	return &sessions.SessionState{
		AccessToken:      p.AccessToken,
		RefreshToken:     p.RefreshToken,
		IDToken:          p.IdToken,
		Email:            p.Email,
		User:             p.User,
		Groups:           p.Groups,
		RefreshDeadline:  refreshDeadline,
		LifetimeDeadline: lifetimeDeadline,
	}, nil
}

// ProtoFromSession converts a pomerium user session into a protocol buffer struct.
func ProtoFromSession(s *sessions.SessionState) (*Session, error) {
	if s == nil {
		return nil, fmt.Errorf("proto/authenticate: ProtoFromSession session cannot be nil")
	}
	lifetimeDeadline, err := ptypes.TimestampProto(s.LifetimeDeadline)
	if err != nil {
		return nil, fmt.Errorf("proto/authenticate: couldn't parse lifetime deadline %v", err)
	}
	refreshDeadline, err := ptypes.TimestampProto(s.RefreshDeadline)
	if err != nil {
		return nil, fmt.Errorf("proto/authenticate: couldn't parse refresh deadline %v", err)
	}
	return &Session{
		AccessToken:      s.AccessToken,
		RefreshToken:     s.RefreshToken,
		IdToken:          s.IDToken,
		Email:            s.Email,
		User:             s.User,
		Groups:           s.Groups,
		RefreshDeadline:  refreshDeadline,
		LifetimeDeadline: lifetimeDeadline,
	}, nil
}
