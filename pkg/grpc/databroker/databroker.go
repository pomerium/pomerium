// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"io"
	"strings"

	"google.golang.org/protobuf/proto"
)

// GetUserID gets the databroker user id from a provider user id.
func GetUserID(provider, providerUserID string) string {
	return provider + "/" + providerUserID
}

// FromUserID gets the provider and provider user id from a databroker user id.
func FromUserID(userID string) (provider, providerUserID string) {
	ps := strings.SplitN(userID, "/", 2)
	if len(ps) < 2 {
		return "", userID
	}
	return ps[0], ps[1]
}

// ApplyOffsetAndLimit applies the offset and limit to the list of records.
func ApplyOffsetAndLimit(all []*Record, offset, limit int) (records []*Record, totalCount int) {
	records = all
	if offset < len(records) {
		records = records[offset:]
	} else {
		records = nil
	}
	if limit <= len(records) {
		records = records[:limit]
	}
	return records, len(all)
}

// InitialSync performs a sync with no_wait set to true and then returns all the results.
func InitialSync(ctx context.Context, client DataBrokerServiceClient, in *SyncRequest) (*SyncResponse, error) {
	dup := new(SyncRequest)
	proto.Merge(dup, in)
	dup.NoWait = true

	stream, err := client.Sync(ctx, dup)
	if err != nil {
		return nil, err
	}

	finalRes := &SyncResponse{}

loop:
	for {
		res, err := stream.Recv()
		switch {
		case err == io.EOF:
			break loop
		case err != nil:
			return nil, err
		}

		finalRes.ServerVersion = res.GetServerVersion()
		finalRes.Records = append(finalRes.Records, res.GetRecords()...)
	}

	return finalRes, nil
}
