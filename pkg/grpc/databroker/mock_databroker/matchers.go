package mock_databroker //nolint:revive,stylecheck

import (
	"fmt"

	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func DeleteRequestFor(records ...*databroker.Record) gomock.Matcher {
	return deleteRequestMatcher{records}
}

type deleteRequestMatcher struct {
	expected []*databroker.Record
}

func (m deleteRequestMatcher) Matches(x any) bool {
	p, ok := x.(*databroker.PutRequest)
	if !ok {
		return false
	} else if len(p.Records) != len(m.expected) {
		return false
	}
	for i := range p.Records {
		if !proto.Equal(p.Records[i].Data, m.expected[i].Data) {
			return false
		}
		if p.Records[i].DeletedAt == nil {
			return false
		}
	}
	return true
}

func (m deleteRequestMatcher) String() string {
	return fmt.Sprintf("is PutRequest to delete %v", m.expected)
}
