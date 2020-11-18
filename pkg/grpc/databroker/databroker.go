// Package databroker contains databroker protobuf definitions.
package databroker

import (
	context "context"
	"strings"
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

// GetAllPages calls GetAll for all pages of data.
func GetAllPages(ctx context.Context, client DataBrokerServiceClient, in *GetAllRequest) (*GetAllResponse, error) {
	var res GetAllResponse
	var pageToken string
	for {
		nxt, err := client.GetAll(ctx, &GetAllRequest{
			Type:      in.GetType(),
			PageToken: pageToken,
		})
		if err != nil {
			return nil, err
		}

		res.ServerVersion = nxt.ServerVersion
		res.RecordVersion = nxt.RecordVersion
		res.Records = append(res.Records, nxt.Records...)

		if nxt.NextPageToken == "" {
			break
		}
		pageToken = nxt.NextPageToken
	}
	return &res, nil
}
