// Package databroker contains databroker protobuf definitions.
package databroker

// GetUserID gets the databroker user id from a provider user id.
func GetUserID(provider, providerUserID string) string {
	return provider + "/" + providerUserID
}
