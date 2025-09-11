package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/internal/urlutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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
	ClusterLeaderID             null.String            `mapstructure:"databroker_cluster_leader_id" yaml:"databroker_cluster_leader_id,omitempty"`
	ClusterNodeID               null.String            `mapstructure:"databroker_cluster_node_id" yaml:"databroker_cluster_node_id,omitempty"`
	ClusterNodes                DataBrokerClusterNodes `mapstructure:"databroker_cluster_nodes" yaml:"databroker_cluster_nodes,omitempty"`
	InternalServiceURL          string                 `mapstructure:"databroker_internal_service_url" yaml:"databroker_internal_service_url,omitempty"`
	RaftBindAddress             null.String            `mapstructure:"databroker_raft_bind_address" yaml:"databroker_raft_bind_address,omitempty"`
	ServiceURL                  string                 `mapstructure:"databroker_service_url" yaml:"databroker_service_url,omitempty"`
	ServiceURLs                 []string               `mapstructure:"databroker_service_urls" yaml:"databroker_service_urls,omitempty"`
	StorageConnectionString     string                 `mapstructure:"databroker_storage_connection_string" yaml:"databroker_storage_connection_string,omitempty"`
	StorageConnectionStringFile string                 `mapstructure:"databroker_storage_connection_string_file" yaml:"databroker_storage_connection_string_file,omitempty"`
	StorageType                 string                 `mapstructure:"databroker_storage_type" yaml:"databroker_storage_type,omitempty"`
}

// GetStorageConnectionString gets the databroker storage connection string from either a file
// or the config option directly. If from a file spaces are trimmed off the ends.
func (o *DataBrokerOptions) GetStorageConnectionString() (string, error) {
	if o.StorageConnectionStringFile != "" {
		bs, err := os.ReadFile(o.StorageConnectionStringFile)
		return strings.TrimSpace(string(bs)), err
	}

	return o.StorageConnectionString, nil
}

// FromProto sets options from a config settings protobuf.
func (o *DataBrokerOptions) FromProto(src *configpb.Settings) {
	setNullableString(&o.ClusterLeaderID, src.DatabrokerClusterLeaderId)
	setNullableString(&o.ClusterNodeID, src.DatabrokerClusterNodeId)
	o.ClusterNodes.FromProto(src.DatabrokerClusterNodes)
	setNullableString(&o.RaftBindAddress, src.DatabrokerRaftBindAddress)
	setSlice(&o.ServiceURLs, src.DatabrokerServiceUrls)
	set(&o.InternalServiceURL, src.DatabrokerInternalServiceUrl)
	set(&o.StorageType, src.DatabrokerStorageType)
	set(&o.StorageConnectionString, src.DatabrokerStorageConnectionString)
}

// ToProto updates a config settings protobuf with databroker options.
func (o *DataBrokerOptions) ToProto(dst *configpb.Settings) {
	dst.DatabrokerClusterLeaderId = o.ClusterLeaderID.Ptr()
	dst.DatabrokerClusterNodeId = o.ClusterNodeID.Ptr()
	o.ClusterNodes.ToProto(&dst.DatabrokerClusterNodes)
	copySrcToOptionalDest(&dst.DatabrokerInternalServiceUrl, &o.InternalServiceURL)
	dst.DatabrokerRaftBindAddress = o.RaftBindAddress.Ptr()
	dst.DatabrokerServiceUrls = o.ServiceURLs
	copySrcToOptionalDest(&dst.DatabrokerStorageType, &o.StorageType)
	copySrcToOptionalDest(&dst.DatabrokerStorageConnectionString, valueOrFromFileRaw(o.StorageConnectionString, o.StorageConnectionStringFile))
}

// Validate validates the databroker options.
func (o *DataBrokerOptions) Validate() error {
	switch o.StorageType {
	case StorageInMemoryName:
	case StoragePostgresName, StorageFileName:
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
	for _, node := range o.ClusterNodes {
		_, err := urlutil.ParseAndValidateURL(node.GRPCAddress)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerClusterNodeGRPCAddress, node.GRPCAddress, err)
		}
		if node.RaftAddress.IsValid() {
			_, err := netip.ParseAddrPort(node.RaftAddress.String)
			if err != nil {
				return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerClusterNodeRaftAddress, node.RaftAddress.String, err)
			}
		}
	}

	if o.ClusterLeaderID.IsValid() {
		found := false
		for _, node := range o.ClusterNodes {
			found = found || node.ID == o.ClusterLeaderID.String
		}
		if !found {
			return fmt.Errorf("%w: leader not found in cluster nodes", ErrInvalidDataBrokerClusterLeaderID)
		}
	}
	if o.ClusterNodeID.IsValid() {
		found := false
		for _, node := range o.ClusterNodes {
			found = found || node.ID == o.ClusterNodeID.String
		}
		if !found {
			return fmt.Errorf("%w: node not found in cluster nodes", ErrInvalidDataBrokerClusterNodeID)
		}
	}

	return nil
}

// DataBrokerClusterNode represents a databroker cluster node.
type DataBrokerClusterNode struct {
	ID          string      `mapstructure:"id" yaml:"id,omitempty"`
	GRPCAddress string      `mapstructure:"grpc_address" yaml:"grpc_address,omitempty"`
	RaftAddress null.String `mapstructure:"raft_address" yaml:"raft_address,omitempty"`
}

func (node *DataBrokerClusterNode) FromProto(src *configpb.Settings_DataBrokerClusterNode) {
	node.ID = src.Id
	node.GRPCAddress = src.GrpcAddress
	setNullableString(&node.RaftAddress, src.RaftAddress)
}

func (node DataBrokerClusterNode) ToProto(dst *configpb.Settings_DataBrokerClusterNode) {
	dst.Id = node.ID
	dst.GrpcAddress = node.GRPCAddress
	dst.RaftAddress = node.RaftAddress.Ptr()
}

// DataBrokerClusterNodes is a slice of DataBrokerClusterNode.
type DataBrokerClusterNodes []DataBrokerClusterNode

func (nodes *DataBrokerClusterNodes) FromProto(src *configpb.Settings_DataBrokerClusterNodes) {
	if src == nil {
		return
	}

	if src.Nodes == nil {
		*nodes = nil
		return
	}

	*nodes = make([]DataBrokerClusterNode, len(src.Nodes))
	for i := range src.Nodes {
		(*nodes)[i].FromProto(src.Nodes[i])
	}
}

func (nodes DataBrokerClusterNodes) ToProto(dst **configpb.Settings_DataBrokerClusterNodes) {
	if nodes == nil {
		*dst = nil
		return
	}

	*dst = &configpb.Settings_DataBrokerClusterNodes{
		Nodes: make([]*configpb.Settings_DataBrokerClusterNode, len(nodes)),
	}
	for i := range nodes {
		(*dst).Nodes[i] = new(configpb.Settings_DataBrokerClusterNode)
		nodes[i].ToProto((*dst).Nodes[i])
	}
}
