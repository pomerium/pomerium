// Package databroker contains databroker protobuf definitions.
package databroker

import "strings"

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
