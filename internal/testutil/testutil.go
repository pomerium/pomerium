// Package testutil contains helper functions for unit tests.
package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

// AssertProtoEqual asserts that two protobuf messages equal. Slices of messages are also supported.
func AssertProtoEqual(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	t.Helper()
	return assert.True(t, cmp.Equal(expected, actual, protocmp.Transform()),
		append(msgAndArgs, cmp.Diff(expected, actual, protocmp.Transform()))...)
}

// AssertProtoJSONEqual asserts that a protobuf message matches the given JSON. The protoMsg can also be a slice
// of protobuf messages.
func AssertProtoJSONEqual(t *testing.T, expected string, protoMsg interface{}, msgAndArgs ...interface{}) bool {
	t.Helper()
	protoMsgVal := reflect.ValueOf(protoMsg)
	if protoMsgVal.Kind() == reflect.Slice {
		var protoMsgs []json.RawMessage
		for i := 0; i < protoMsgVal.Len(); i++ {
			protoMsgs = append(protoMsgs, toProtoJSON(protoMsgVal.Index(i).Interface()))
		}
		bs, _ := json.Marshal(protoMsgs)
		return assert.Equal(t, reformatJSON(json.RawMessage(expected)), reformatJSON(bs), msgAndArgs...)
	}

	return assert.Equal(t, reformatJSON(json.RawMessage(expected)), reformatJSON(toProtoJSON(protoMsg)), msgAndArgs...)
}

func reformatJSON(raw json.RawMessage) string {
	var obj interface{}
	_ = json.Unmarshal(raw, &obj)
	bs, _ := json.MarshalIndent(obj, "", "  ")
	return string(bs)
}

func toProtoJSON(protoMsg interface{}) json.RawMessage {
	v2 := proto.MessageV2(protoMsg)
	bs, _ := protojson.Marshal(v2)
	return bs
}

// ModRoot returns the directory containing the go.mod file.
func ModRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic("error getting working directory")
	}

	for {
		if fi, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !fi.IsDir() {
			return dir
		}
		d := filepath.Dir(dir)
		if d == dir {
			break
		}
		dir = d
	}
	return ""
}

// TestDataRoot returns the testdata directory.
func TestDataRoot() string {
	return filepath.Join(ModRoot(), "internal", "testutil", "testdata")
}
