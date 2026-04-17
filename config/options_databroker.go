package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// Errors
var (
	ErrInvalidDataBrokerClusterLeaderID         = errors.New("config: invalid databroker cluster leader id")
	ErrInvalidDataBrokerClusterNodeID           = errors.New("config: invalid databroker cluster node id")
	ErrInvalidDataBrokerClusterNodeGRPCAddress  = errors.New("config: invalid databroker cluster node grpc address")
	ErrInvalidDataBrokerClusterNodeRaftAddress  = errors.New("config: invalid databroker cluster node raft address")
	ErrInvalidDataBrokerServiceURL              = errors.New("config: bad databroker service url")
	ErrInvalidDataBrokerInternalServiceURL      = errors.New("config: bad databroker internal service url")
	ErrMissingDataBrokerStorageConnectionString = errors.New("config: missing databroker storage backend dsn")
	ErrUnknownDataBrokerStorageType             = errors.New("config: unknown databroker storage backend type")
)

// DataBrokerOptions are options related to the databroker.
type DataBrokerOptions struct {
	ClusterLeaderID             null.String
	ClusterNodeID               null.String
	ClusterNodes                *Settings_DataBrokerClusterNodes
	InternalServiceURL          string
	RaftBindAddress             null.String
	ServiceURL                  string
	ServiceURLs                 []string
	StorageConnectionString     string
	StorageConnectionStringFile string
	StorageType                 string
}

func (o *Options) GetDataBrokerOptions() DataBrokerOptions {
	return DataBrokerOptions{
		ClusterLeaderID:             null.StringFromPtr(o.DatabrokerClusterLeaderID),
		ClusterNodeID:               null.StringFromPtr(o.DatabrokerClusterNodeID),
		ClusterNodes:                o.DatabrokerClusterNodes,
		InternalServiceURL:          nilToZero(o.DatabrokerInternalServiceURL),
		RaftBindAddress:             null.StringFromPtr(o.DatabrokerRaftBindAddress),
		ServiceURL:                  nilToZero(o.DatabrokerServiceURL),
		ServiceURLs:                 o.DatabrokerServiceURLs,
		StorageConnectionString:     nilToZero(o.DatabrokerStorageConnectionString),
		StorageConnectionStringFile: nilToZero(o.DatabrokerStorageConnectionStringFile),
		StorageType:                 nilToZero(o.DatabrokerStorageType),
	}
}

// GetStorageConnectionString gets the databroker storage connection string from either a file
// or the config option directly. If from a file spaces are trimmed off the ends.
func (o DataBrokerOptions) GetStorageConnectionString() (string, error) {
	if o.StorageConnectionStringFile != "" {
		bs, err := os.ReadFile(o.StorageConnectionStringFile)
		return strings.TrimSpace(string(bs)), err
	}

	return o.StorageConnectionString, nil
}

// Validate validates the databroker options.
func (o DataBrokerOptions) Validate() error {
	switch o.StorageType {
	case StorageInMemoryName, StorageFileName:
	case StoragePostgresName:
		if o.StorageConnectionString == "" && o.StorageConnectionStringFile == "" {
			return ErrMissingDataBrokerStorageConnectionString
		}
	default:
		return ErrUnknownDataBrokerStorageType
	}

	if o.ServiceURL != "" {
		_, err := urlutil.ParseAndValidateURL(o.ServiceURL)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerServiceURL, o.ServiceURL, err)
		}
	}
	if o.InternalServiceURL != "" {
		_, err := urlutil.ParseAndValidateURL(o.InternalServiceURL)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerInternalServiceURL, o.InternalServiceURL, err)
		}
	}
	for _, str := range o.ServiceURLs {
		_, err := urlutil.ParseAndValidateURL(str)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerServiceURL, str, err)
		}
	}
	if o.ClusterNodes != nil {
		for _, node := range o.ClusterNodes.Nodes {
			_, err := urlutil.ParseAndValidateURL(node.GRPCAddress)
			if err != nil {
				return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerClusterNodeGRPCAddress, node.GRPCAddress, err)
			}
			if node.RaftAddress != nil {
				_, _, err := net.SplitHostPort(*node.RaftAddress)
				if err != nil {
					return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerClusterNodeRaftAddress, *node.RaftAddress, err)
				}
			}
		}
	}

	if o.ClusterLeaderID.IsValid() {
		found := false
		if o.ClusterNodes != nil {
			for _, node := range o.ClusterNodes.Nodes {
				found = found || node.ID == o.ClusterLeaderID.String
			}
		}
		if !found {
			return fmt.Errorf("%w: leader not found in cluster nodes", ErrInvalidDataBrokerClusterLeaderID)
		}
	}
	if o.ClusterNodeID.IsValid() {
		found := false
		if o.ClusterNodes != nil {
			for _, node := range o.ClusterNodes.Nodes {
				found = found || node.ID == o.ClusterNodeID.String
			}
		}
		if !found {
			return fmt.Errorf("%w: node not found in cluster nodes", ErrInvalidDataBrokerClusterNodeID)
		}
	}

	return nil
}
