package manager

import (
	"fmt"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/golang/protobuf/ptypes"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/mitchellh/hashstructure"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/grpc/session"
)

var maxTime = time.Unix(1<<63-62135596801, 999999999)

func getHash(v interface{}) uint64 {
	if v == nil {
		return 0
	}
	h, _ := hashstructure.Hash(v, &hashstructure.HashOptions{
		Hasher: xxhash.New(),
	})
	return h
}

func getMinTime(tms ...time.Time) time.Time {
	min := maxTime
	for _, tm := range tms {
		if tm.Before(min) {
			min = tm
		}
	}
	return min
}

func getStringClaim(claims map[string]*anypb.Any, key string) string {
	if claims == nil {
		return ""
	}

	var str wrapperspb.StringValue
	_ = ptypes.UnmarshalAny(claims[key], &str)
	return str.Value
}

func getStringsClaim(claims map[string]*anypb.Any, key string) []string {
	if claims == nil {
		return nil
	}

	var lst structpb.ListValue
	_ = ptypes.UnmarshalAny(claims[key], &lst)
	strs := make([]string, 0)
	for _, value := range lst.GetValues() {
		if _, ok := value.Kind.(*structpb.Value_StringValue); ok {
			strs = append(strs, value.GetStringValue())
		}
	}
	return strs
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

	case []interface{}:
		lst := &structpb.ListValue{}
		for _, c := range v {
			if cv, err := toValue(c); err == nil {
				lst.Values = append(lst.Values, cv)
			}
		}
		return ptypes.MarshalAny(lst)
	}
	return nil, fmt.Errorf("unknown type %T", value)
}

func toValue(value interface{}) (*structpb.Value, error) {
	switch v := value.(type) {
	case bool:
		return &structpb.Value{
			Kind: &structpb.Value_BoolValue{BoolValue: v},
		}, nil
	case float64:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: v},
		}, nil
	case float32:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: float64(v)},
		}, nil
	case int32:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: float64(v)},
		}, nil
	case int64:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: float64(v)},
		}, nil
	case string:
		return &structpb.Value{
			Kind: &structpb.Value_StringValue{StringValue: v},
		}, nil
	case uint32:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: float64(v)},
		}, nil
	case uint64:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{NumberValue: float64(v)},
		}, nil

	}
	return nil, fmt.Errorf("unknown type %T", value)
}

func toSessionSchedulerKey(userID, sessionID string) string {
	return userID + "\037" + sessionID
}

func fromSessionSchedulerKey(key string) (userID, sessionID string) {
	idx := strings.Index(key, "\037")
	if idx >= 0 {
		userID = key[:idx]
		sessionID = key[idx+1:]
	} else {
		userID = key
	}
	return userID, sessionID
}

func fromOAuthToken(token *session.OAuthToken) *oauth2.Token {
	expiry, _ := ptypes.Timestamp(token.GetExpiresAt())
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       expiry,
	}
}

func toOAuthToken(token *oauth2.Token) *session.OAuthToken {
	expiry, _ := ptypes.TimestampProto(token.Expiry)
	return &session.OAuthToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    expiry,
	}
}
