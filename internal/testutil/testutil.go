// Package testutil contains helper functions for unit tests.
package testutil

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"
)

const maxWait = time.Minute * 20

// AssertProtoEqual asserts that two protobuf messages equal. Slices of messages are also supported.
func AssertProtoEqual(t *testing.T, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	return assert.True(t, cmp.Equal(expected, actual, protocmp.Transform()),
		append(msgAndArgs, cmp.Diff(expected, actual, protocmp.Transform()))...)
}

// AssertProtoJSONEqual asserts that a protobuf message matches the given JSON. The protoMsg can also be a slice
// of protobuf messages.
func AssertProtoJSONEqual(t *testing.T, expectedJSON string, protoMsg any, msgAndArgs ...any) bool {
	t.Helper()
	var expected any
	err := json.Unmarshal([]byte(expectedJSON), &expected)
	require.NoError(t, err)

	var proto any
	err = json.Unmarshal([]byte(formattedProtoJSON(protoMsg)), &proto)
	require.NoError(t, err)

	diff := cmp.Diff(expected, proto)
	return assert.Empty(t, diff, msgAndArgs...)
}

func formattedProtoJSON(protoMsg any) string {
	protoMsgVal := reflect.ValueOf(protoMsg)
	if protoMsgVal.Kind() == reflect.Slice {
		var protoMsgs []json.RawMessage
		for i := 0; i < protoMsgVal.Len(); i++ {
			protoMsgs = append(protoMsgs, toProtoJSON(protoMsgVal.Index(i).Interface()))
		}
		bs, _ := json.Marshal(protoMsgs)
		return reformatJSON(bs)
	}
	return reformatJSON(toProtoJSON(protoMsg))
}

func reformatJSON(raw json.RawMessage) string {
	var obj any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.Decode(&obj)
	bs, _ := json.MarshalIndent(obj, "", "  ")
	return string(bs)
}

func toProtoJSON(protoMsg any) json.RawMessage {
	bs, _ := protojson.Marshal(protoMsg.(protoreflect.ProtoMessage))
	return bs
}

var updateFlag = flag.Bool("update", false,
	"when enabled, reference files will be updated to match current behavior")

// AssertProtoJSONFileEqual asserts that a protobuf message (or slice of
// messages) matches the given reference JSON file.
//
// To update a reference JSON file, pass the test argument '-update'. This will
// overwrite the reference output to match the current behavior.
func AssertProtoJSONFileEqual(
	t *testing.T, file string, protoMsg any, msgAndArgs ...any,
) bool {
	t.Helper()

	if *updateFlag {
		updatedJSON := formattedProtoJSON(protoMsg) + "\n"
		err := os.WriteFile(file, []byte(updatedJSON), 0o644)
		return assert.NoError(t, err)
	}

	expected, err := os.ReadFile(file)
	require.NoError(t, err)

	return AssertProtoJSONEqual(t, string(expected), protoMsg, msgAndArgs...)
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

// AssertJSONEqual does the same thing as assert.JSONEq but uses the json number type for numbers.
func AssertJSONEqual(t *testing.T, expected, actual string, msgAndArgs ...any) bool {
	t.Helper()
	return assert.Equal(t,
		reformatJSON(json.RawMessage(expected)),
		reformatJSON(json.RawMessage(actual)),
		msgAndArgs...)
}
