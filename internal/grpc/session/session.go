package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type idTokenFiller struct {
	*Session
}

func (f idTokenFiller) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	f.Session.IdToken = new(IDToken)

	if iss, ok := raw["iss"]; !ok {
		err = fmt.Errorf("iss not found in id token")
	} else {
		err = json.Unmarshal(iss, &f.Session.IdToken.Issuer)
		delete(raw, "iss")
	}
	if err != nil {
		return err
	}

	if sub, ok := raw["sub"]; !ok {
		err = fmt.Errorf("sub not found in id token")
	} else {
		err = json.Unmarshal(sub, &f.Session.IdToken.Subject)
		delete(raw, "sub")
	}
	if err != nil {
		return err
	}

	if exp, ok := raw["exp"]; ok {
		var secs int64
		if err := json.Unmarshal(exp, &secs); err == nil {
			f.Session.IdToken.ExpiresAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "exp")
	}

	if iat, ok := raw["iat"]; ok {
		var secs int64
		if err := json.Unmarshal(iat, &secs); err == nil {
			f.Session.IdToken.ExpiresAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "iat")
	}

	f.Session.IdToken.Claims = make(map[string]*anypb.Any)
	for k, rawv := range raw {
		var v interface{}
		if json.Unmarshal(rawv, &v) != nil {
			continue
		}

		if anyv, err := toAny(v); err == nil {
			f.Session.IdToken.Claims[k] = anyv
		}
	}

	return nil
}

func toAny(value interface{}) (*anypb.Any, error) {
	switch v := value.(type) {
	case bool:
		return ptypes.MarshalAny(&wrapperspb.BoolValue{Value: v})
	case []byte:
		return ptypes.MarshalAny(&wrapperspb.BytesValue{Value: v})
	case float64:
		return ptypes.MarshalAny(&wrapperspb.DoubleValue{Value: v})
	case float32:
		return ptypes.MarshalAny(&wrapperspb.FloatValue{Value: v})
	case int32:
		return ptypes.MarshalAny(&wrapperspb.Int32Value{Value: v})
	case int64:
		return ptypes.MarshalAny(&wrapperspb.Int64Value{Value: v})
	case string:
		return ptypes.MarshalAny(&wrapperspb.StringValue{Value: v})
	case uint32:
		return ptypes.MarshalAny(&wrapperspb.UInt32Value{Value: v})
	case uint64:
		return ptypes.MarshalAny(&wrapperspb.UInt64Value{Value: v})
	}
	return nil, fmt.Errorf("unknown type %T", value)
}

// IDTokenJSONFiller returns a json.Unmarshaler suitable for JSON-decoding an id token response.
func (s *Session) IDTokenJSONFiller() json.Unmarshaler {
	return idTokenFiller{s}
}
