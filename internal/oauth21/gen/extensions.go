package gen

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/mapsutil"
)

// IDPSession implements identity.State

func (x *IDPSession) SetRawIDToken(rawIDToken string) {
	if x == nil {
		return
	}
	x.RawIdToken = rawIDToken
}

func (x *IDPSession) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.GetClaims().AsMap())
}

func (x *IDPSession) UnmarshalJSON(data []byte) error {
	if x == nil {
		return nil
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}

	merged := x.GetClaims().AsMap()
	if merged == nil {
		merged = make(map[string]any, len(raw))
	}
	for k, v := range mapsutil.Flatten(raw) {
		merged[k] = v
	}

	claims, err := structpb.NewStruct(merged)
	if err != nil {
		return err
	}
	x.Claims = claims

	return nil
}
