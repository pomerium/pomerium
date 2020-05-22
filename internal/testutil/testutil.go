// Package testutil contains helper functions for unit tests.
package testutil

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

// AssertProtoJSONEqual asserts that a protobuf message matches the given JSON. The protoMsg can also be a slice
// of protobuf messages.
func AssertProtoJSONEqual(t *testing.T, expected string, protoMsg interface{}, msgAndArgs ...interface{}) bool {
	protoMsgVal := reflect.ValueOf(protoMsg)
	if protoMsgVal.Kind() == reflect.Slice {
		var protoMsgs []json.RawMessage
		for i := 0; i < protoMsgVal.Len(); i++ {
			protoMsgs = append(protoMsgs, toProtoJSON(protoMsgVal.Index(i).Interface()))
		}
		bs, _ := json.Marshal(protoMsgs)
		return assert.JSONEq(t, expected, string(bs), msgAndArgs...)
	}

	return assert.JSONEq(t, expected, string(toProtoJSON(protoMsg)), msgAndArgs...)
}

func toProtoJSON(protoMsg interface{}) json.RawMessage {
	v2 := proto.MessageV2(protoMsg)
	bs, _ := protojson.Marshal(v2)
	return bs
}
