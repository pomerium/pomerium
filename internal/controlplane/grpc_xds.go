package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/pomerium/pomerium/internal/log"
	"golang.org/x/sync/errgroup"
)

func (srv *Server) registerXDSHandlers() {
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv)
}

// StreamAggregatedResources streams xDS resources based on incoming discovery requests.
//
// This is setup as 3 concurrent goroutines:
// - The first retrieves the requests from the client.
// - The third sends responses back to the client.
// - The second waits for either the client to request a new resource type
//   or for the config to have been updated
//   - in either case, we loop over all of the current client versions
//     and if any of them are different from the current version, we send
//     the updated resource
func (srv *Server) StreamAggregatedResources(stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	versions := map[string]string{}
	incoming := make(chan *envoy_service_discovery_v3.DiscoveryRequest)
	outgoing := make(chan *envoy_service_discovery_v3.DiscoveryResponse)

	eg, ctx := errgroup.WithContext(stream.Context())
	// receive requests
	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				return err
			}

			select {
			case incoming <- req:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	eg.Go(func() error {
		for {
			select {
			case req := <-incoming:
				if req.ErrorDetail != nil {
					bs, _ := json.Marshal(req.ErrorDetail.Details)
					log.Error().
						Err(errors.New(req.ErrorDetail.Message)).
						Int32("code", req.ErrorDetail.Code).
						RawJSON("details", bs).Msg("error applying configuration")
					continue
				}

				// update the currently stored version
				// if this version is different from the current version
				// we will send the response below
				versions[req.TypeUrl] = req.VersionInfo
			case <-srv.configUpdated:
			case <-ctx.Done():
				return ctx.Err()
			}

			current := srv.currentConfig.Load().(versionedOptions)
			for typeURL, version := range versions {
				// the versions are different, so the envoy config needs to be updated
				if version != fmt.Sprint(current.version) {
					res, err := srv.buildDiscoveryResponse(fmt.Sprint(current.version), typeURL, current.Options)
					if err != nil {
						return err
					}
					select {
					case outgoing <- res:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
	})
	// send responses
	eg.Go(func() error {
		for {
			var res *envoy_service_discovery_v3.DiscoveryResponse
			select {
			case res = <-outgoing:
			case <-ctx.Done():
				return ctx.Err()
			}

			err := stream.Send(res)
			if err != nil {
				return err
			}
		}
	})
	return eg.Wait()
}

// DeltaAggregatedResources is not implemented.
func (srv *Server) DeltaAggregatedResources(in envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	return fmt.Errorf("DeltaAggregatedResources not implemented")
}
