package handlers

import (
	"encoding/json"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/ui"
)

// UserInfoData is the data for the UserInfo page.
type UserInfoData struct {
	DirectoryGroups []*directory.Group
	DirectoryUser   *directory.User
	Session         *session.Session
	User            *user.User
}

// MarshalJSON encodes the user info data as JSON.
func (data UserInfoData) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	var directoryGroups []json.RawMessage
	for _, directoryGroup := range data.DirectoryGroups {
		if bs, err := protojson.Marshal(directoryGroup); err == nil {
			directoryGroups = append(directoryGroups, json.RawMessage(bs))
		}
	}
	m["directoryGroups"] = directoryGroups
	if bs, err := protojson.Marshal(data.DirectoryUser); err == nil {
		m["directoryUser"] = json.RawMessage(bs)
	}
	if bs, err := protojson.Marshal(data.Session); err == nil {
		m["session"] = json.RawMessage(bs)
	}
	if bs, err := protojson.Marshal(data.User); err == nil {
		m["user"] = json.RawMessage(bs)
	}
	return json.Marshal(m)
}

// UserInfo returns a handler that renders the user info page.
func UserInfo(data UserInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServeUserInfo(w, r, data)
	})
}
