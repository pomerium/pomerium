package matchers

import (
	"fmt"

	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
)

// ProtoEq returns a matcher for the given proto message.
func ProtoEq(expected proto.Message) gomock.Matcher {
	return protoEqualMatcher{expected}
}

// protoEqualMatcher implements gomock.Matcher using proto.Equal.
type protoEqualMatcher struct {
	expected proto.Message
}

func (m protoEqualMatcher) Matches(x any) bool {
	p, ok := x.(proto.Message)
	if !ok {
		return false
	}
	return proto.Equal(m.expected, p)
}

func (m protoEqualMatcher) String() string {
	return fmt.Sprintf("is equal to %v (%T)", m.expected, m.expected)
}
