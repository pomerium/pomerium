package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/internal/urlutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Errors
var (
	ErrInvalidDataBrokerClusterNodeURL          = errors.New("config: invalid databroker cluster node url")
	ErrInvalidDataBrokerServiceURL              = errors.New("config: bad databroker service url")
	ErrInvalidDataBrokerInternalServiceURL      = errors.New("config: bad databroker internal service url")
	ErrMissingDataBrokerStorageConnectionString = errors.New("config: missing databroker storage backend dsn")
	ErrUnknownDataBrokerStorageType             = errors.New("config: unknown databroker storage backend type")
)

// DataBrokerOptions are options related to the databroker.
type DataBrokerOptions struct {
	ClusterNodeID               null.String            `mapstructure:"databroker_cluster_node_id" yaml:"databroker_cluster_node_id,omitempty"`
	ClusterNodes                DataBrokerClusterNodes `mapstructure:"databroker_cluster_nodes" yaml:"databroker_cluster_nodes,omitempty"`
	InternalServiceURL          string                 `mapstructure:"databroker_internal_service_url" yaml:"databroker_internal_service_url,omitempty"`
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
	setNullableString(&o.ClusterNodeID, src.DatabrokerClusterNodeId)
	o.ClusterNodes.FromProto(src.DatabrokerClusterNodes)
	setSlice(&o.ServiceURLs, src.DatabrokerServiceUrls)
	set(&o.InternalServiceURL, src.DatabrokerInternalServiceUrl)
	set(&o.StorageType, src.DatabrokerStorageType)
	set(&o.StorageConnectionString, src.DatabrokerStorageConnectionString)
}

// ToProto updates a config settings protobuf with databroker options.
func (o *DataBrokerOptions) ToProto(dst *configpb.Settings) {
	dst.DatabrokerClusterNodeId = o.ClusterNodeID.Ptr()
	o.ClusterNodes.ToProto(&dst.DatabrokerClusterNodes)
	dst.DatabrokerServiceUrls = o.ServiceURLs
	copySrcToOptionalDest(&dst.DatabrokerInternalServiceUrl, &o.InternalServiceURL)
	copySrcToOptionalDest(&dst.DatabrokerStorageType, &o.StorageType)
	copySrcToOptionalDest(&dst.DatabrokerStorageConnectionString, valueOrFromFileRaw(o.StorageConnectionString, o.StorageConnectionStringFile))
}

// Validate validates the databroker options.
func (o *DataBrokerOptions) Validate() error {
	switch o.StorageType {
	case StorageInMemoryName:
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
	for _, node := range o.ClusterNodes {
		_, err := urlutil.ParseAndValidateURL(node.URL)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerClusterNodeURL, node.URL, err)
		}
	}

	return nil
}

// DataBrokerClusterNode represents a databroker cluster node.
type DataBrokerClusterNode struct {
	ID  string `mapstructure:"id" yaml:"id,omitempty"`
	URL string `mapstructure:"url" yaml:"url,omitempty"`
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
	for i, n := range src.Nodes {
		(*nodes)[i] = DataBrokerClusterNode{
			ID:  n.Id,
			URL: n.Url,
		}
	}
}

func (nodes DataBrokerClusterNodes) ToProto(dst **configpb.Settings_DataBrokerClusterNodes) {
	if nodes == nil {
		*dst = nil
		return
	}

	*dst = new(configpb.Settings_DataBrokerClusterNodes)
	for _, n := range nodes {
		(*dst).Nodes = append((*dst).Nodes, &configpb.Settings_DataBrokerClusterNode{
			Id:  n.ID,
			Url: n.URL,
		})
	}
}
