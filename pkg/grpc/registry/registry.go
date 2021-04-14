// Package registry contains protobuf messages related to the service registry.
package registry

import (
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// MetadataKeyEnvoyConfigurationEvents is used for storing envoy configuration events in the registry.
	MetadataKeyEnvoyConfigurationEvents = "envoy_configuration_events"
)

// GetEnvoyConfigurationEvents gets the envoy configuration events from the metadata on the register request.
func (req *RegisterRequest) GetEnvoyConfigurationEvents() ([]*EnvoyConfigurationEvent, error) {
	if req.Metadata == nil {
		return nil, nil
	}
	any, ok := req.Metadata[MetadataKeyEnvoyConfigurationEvents]
	if !ok {
		return nil, nil
	}

	var lst EnvoyConfigurationEvents
	err := any.UnmarshalTo(&lst)
	if err != nil {
		return nil, err
	}

	return lst.Values, nil
}

// SetEnvoyConfigurationEvents sets the envoy configuration events in the metadata on the register request.
func (req *RegisterRequest) SetEnvoyConfigurationEvents(events []*EnvoyConfigurationEvent) error {
	lst := &EnvoyConfigurationEvents{
		Values: events,
	}

	any, err := anypb.New(lst)
	if err != nil {
		return err
	}

	if req.Metadata == nil {
		req.Metadata = make(map[string]*anypb.Any)
	}
	req.Metadata[MetadataKeyEnvoyConfigurationEvents] = any
	return nil
}
