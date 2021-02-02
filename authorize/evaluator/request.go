package evaluator

import (
	"net/url"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

type (
	// Request is the request data used for the evaluator.
	Request struct {
		HTTP           RequestHTTP    `json:"http"`
		Session        RequestSession `json:"session"`
		CustomPolicies []string
		ClientCA       string // pem-encoded certificate authority
	}

	// RequestHTTP is the HTTP field in the request.
	RequestHTTP struct {
		Method            string            `json:"method"`
		URL               string            `json:"url"`
		Headers           map[string]string `json:"headers"`
		ClientCertificate string            `json:"client_certificate"`
	}

	// RequestSession is the session field in the request.
	RequestSession struct {
		ID string `json:"id"`
	}
)

type sessionOrServiceAccount interface {
	GetId() string
	GetExpiresAt() *timestamppb.Timestamp
	GetIssuedAt() *timestamppb.Timestamp
	GetUserId() string
	GetImpersonateEmail() string
	GetImpersonateGroups() []string
	GetImpersonateUserId() string
}

func (req *Request) fillJWTPayload(store *Store, payload map[string]interface{}) {
	if u, err := url.Parse(req.HTTP.URL); err == nil {
		payload["aud"] = u.Hostname()
	}

	if s, ok := store.GetRecordData("type.googleapis.com/session.Session", req.Session.ID).(*session.Session); ok {
		req.fillJWTPayloadSessionOrServiceAccount(store, payload, s)
	}

	if sa, ok := store.GetRecordData("type.googleapis.com/user.ServiceAccount", req.Session.ID).(*user.ServiceAccount); ok {
		req.fillJWTPayloadSessionOrServiceAccount(store, payload, sa)
	}
}

func (req *Request) fillJWTPayloadSessionOrServiceAccount(store *Store, payload map[string]interface{}, s sessionOrServiceAccount) {
	payload["jti"] = s.GetId()
	if s.GetExpiresAt().IsValid() {
		payload["exp"] = s.GetExpiresAt().AsTime().Unix()
	}
	if s.GetIssuedAt().IsValid() {
		payload["iat"] = s.GetIssuedAt().AsTime().Unix()
	}

	userID := s.GetUserId()
	if s.GetImpersonateUserId() != "" {
		userID = s.GetImpersonateUserId()
	}
	if u, ok := store.GetRecordData("type.googleapis.com/user.User", userID).(*user.User); ok {
		payload["sub"] = u.GetId()
		payload["user"] = u.GetId()
		payload["email"] = u.GetEmail()
	}
	if du, ok := store.GetRecordData("type.googleapis.com/directory.User", userID).(*directory.User); ok {
		if du.GetEmail() != "" {
			payload["email"] = du.GetEmail()
		}
		var groupNames []string
		for _, groupID := range du.GetGroupIds() {
			if dg, ok := store.GetRecordData("type.googleapis.com/directory.Group", groupID).(*directory.Group); ok {
				groupNames = append(groupNames, dg.Name)
			}
		}
		var groups []string
		groups = append(groups, du.GetGroupIds()...)
		groups = append(groups, groupNames...)
		payload["groups"] = groups
	}

	if s.GetImpersonateEmail() != "" {
		payload["email"] = s.GetImpersonateEmail()
	}
	if len(s.GetImpersonateGroups()) > 0 {
		payload["groups"] = s.GetImpersonateGroups()
	}
}
