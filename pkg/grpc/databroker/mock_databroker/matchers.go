package mock_databroker

import (
	"fmt"

	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func PutRequestFor(records ...*databroker.Record) gomock.Matcher {
	return putRequestMatcher{expected: records}
}

func DeleteRequestFor(records ...*databroker.Record) gomock.Matcher {
	return putRequestMatcher{expected: records, wantDeleted: true}
}

type putRequestMatcher struct {
	expected    []*databroker.Record
	wantDeleted bool
}

func (m putRequestMatcher) Matches(x any) bool {
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
		hasDeletedAt := p.Records[i].DeletedAt != nil
		if hasDeletedAt != m.wantDeleted {
			return false
		}
	}
	return true
}

func (m putRequestMatcher) String() string {
	if m.wantDeleted {
		return fmt.Sprintf("is PutRequest to delete %v", m.expected)
	}
	return fmt.Sprintf("is PutRequest for %v", m.expected)
}
