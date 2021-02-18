// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// TypeURLs for Any.
const (
	ConfigTypeURL         = "type.googleapis.com/pomerium.config.Config"
	DirectoryGroupTypeURL = "type.googleapis.com/directory.Group"
	DirectoryUserTypeURL  = "type.googleapis.com/directory.User"
	SessionTypeURL        = "type.googleapis.com/session.Session"
	ServiceAccountTypeURL = "type.googleapis.com/user.ServiceAccount"
	UserTypeURL           = "type.googleapis.com/user.User"
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

// InitialSync performs a sync latest and then returns all the results.
func InitialSync(
	ctx context.Context,
	client DataBrokerServiceClient,
	req *SyncLatestRequest,
) (records []*Record, recordVersion, serverVersion uint64, err error) {
	stream, err := client.SyncLatest(ctx, req)
	if err != nil {
		return nil, 0, 0, err
	}

loop:
	for {
		res, err := stream.Recv()
		switch {
		case err == io.EOF:
			break loop
		case err != nil:
			return nil, 0, 0, err
		}

		switch res := res.GetResponse().(type) {
		case *SyncLatestResponse_Versions:
			recordVersion = res.Versions.GetLatestRecordVersion()
			serverVersion = res.Versions.GetServerVersion()
		case *SyncLatestResponse_Record:
			records = append(records, res.Record)
		default:
			panic(fmt.Sprintf("unexpected response: %T", res))
		}
	}

	return records, recordVersion, serverVersion, nil
}
