package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/internal/tcptunnel"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// LoadSaver provides interface to the configuration persistence
type LoadSaver interface {
	// Load returns configuration data,
	// should not throw an error if underlying storage does not exist
	Load() ([]byte, error)
	// Save stores data into storage
	Save([]byte) error
}

const maxConfigFileBytes = 4 << 20

// FileLoadSaver implements file based configuration storage
type FileLoadSaver string

// Load loads file data or returns empty data if it does not exist
func (f FileLoadSaver) Load() ([]byte, error) {
	fd, err := os.Open(string(f))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	defer func() { _ = fd.Close() }()
	return io.ReadAll(io.LimitReader(fd, maxConfigFileBytes))
}

// Save stores data to the file
func (f FileLoadSaver) Save(data []byte) error {
	return os.WriteFile(string(f), data, 0600)
}

type configServer struct {
	sync.RWMutex
	LoadSaver
	*config
}

// ConfigServer implements both config and tunnel interfaces
type ConfigServer interface {
	pb.ConfigServer
	TunnelProvider
}

// NewConfigServer creates new configuration management server
func NewConfigServer(ls LoadSaver) (ConfigServer, error) {
	srv := &configServer{
		LoadSaver: ls,
	}

	cfg, err := loadConfig(ls)
	if err != nil {
		return nil, err
	}
	srv.config = cfg
	return srv, nil
}

func (s *configServer) List(_ context.Context, sel *pb.Selector) (*pb.Records, error) {
	s.RLock()
	defer s.RUnlock()

	if sel.GetAll() {
		return s.config.listAll(), nil
	} else if sel.GetIds() != nil {
		return s.config.listByIDs(sel.GetIds().GetIds())
	} else if sel.GetTags() != nil {
		return s.config.listByTags(sel.GetTags().GetTags())
	}
	return nil, status.Error(codes.InvalidArgument, "either all, ids or tags filter must be specified")
}

func (s *configServer) Delete(context.Context, *pb.Selector) (*pb.DeleteRecordsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Export not implemented")
}

func (s *configServer) Upsert(_ context.Context, r *pb.Record) (*pb.Record, error) {
	s.Lock()
	defer s.Unlock()

	if err := s.config.clearTags(r); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.config.upsert(r)
	if err := s.config.save(s.LoadSaver); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return r, nil
}

func (s *configServer) Export(ctx context.Context, req *pb.ExportRequest) (*pb.ConfigData, error) {
	rec, err := s.List(ctx, req.Selector)
	if err != nil {
		return nil, err
	}

	rec = proto.Clone(rec).(*pb.Records)
	for _, r := range rec.Records {
		r.Id = nil
		if req.RemoveTags {
			r.Tags = nil
		}
	}

	any := protoutil.NewAny(rec)
	opts := protojson.MarshalOptions{}
	if req.Format == pb.ExportRequest_EXPORT_FORMAT_JSON_PRETTY {
		opts.Multiline = true
		opts.Indent = ""
	}
	data, err := opts.Marshal(any)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	return &pb.ConfigData{Data: data}, nil
}

func (s *configServer) Import(_ context.Context, req *pb.ImportRequest) (*pb.ImportResponse, error) {
	any := new(anypb.Any)
	if err := protojson.Unmarshal(req.Data, any); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	records := new(pb.Records)
	if err := anypb.UnmarshalTo(any, records, proto.UnmarshalOptions{}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	s.Lock()
	defer s.Unlock()

	for _, r := range records.Records {
		if req.OverrideTag != nil {
			r.Tags = []string{*req.OverrideTag}
		}
		// TODO: add deduplication
		s.config.upsert(r)
	}

	return &pb.ImportResponse{}, nil
}

func (s *configServer) NewTunnel(id string) (*tcptunnel.Tunnel, string, error) {
	s.RLock()
	defer s.RUnlock()

	rec := s.config.byID[id]
	if rec == nil {
		return nil, "", fmt.Errorf("%s: no such connection", id)
	}

	conn := rec.GetConn()
	if conn == nil {
		return nil, "", fmt.Errorf("%s: no connection info", id)
	}
	listenAddr := "127.0.0.1:0"
	if conn.ListenAddr != nil {
		listenAddr = *conn.ListenAddr
	}

	pxy, err := getProxy(conn)
	if err != nil {
		return nil, "", err
	}

	var tlsCfg *tls.Config
	if pxy.Scheme == "https" {
		tlsCfg, err = getTLSConfig(conn)
		if err != nil {
			return nil, "", fmt.Errorf("tls: %w", err)
		}
	}

	return tcptunnel.New(
		tcptunnel.WithDestinationHost(conn.GetRemoteAddr()),
		tcptunnel.WithProxyHost(pxy.Host),
		tcptunnel.WithTLSConfig(tlsCfg),
	), listenAddr, nil
}

func getProxy(conn *pb.Connection) (*url.URL, error) {
	host, _, err := net.SplitHostPort(conn.GetRemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", conn.GetRemoteAddr(), err)
	}

	if conn.PomeriumUrl == nil {
		return &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(host, "443"),
		}, nil
	}

	u, err := url.Parse(conn.GetPomeriumUrl())
	if err != nil {
		return nil, fmt.Errorf("invalid pomerium url: %w", err)
	}
	if u.Host == u.Hostname() {
		if u.Scheme == "https" {
			u.Host = net.JoinHostPort(u.Host, "443")
		} else {
			u.Host = net.JoinHostPort(u.Host, "80")
		}
	}

	return u, nil
}

func getTLSConfig(conn *pb.Connection) (*tls.Config, error) {
	cfg := &tls.Config{
		//nolint: gosec
		InsecureSkipVerify: conn.GetDisableTlsVerification(),
	}
	if len(conn.GetCaCert()) == 0 {
		return cfg, nil
	}

	rootCA, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("get system cert pool: %w", err)
	}
	if ok := rootCA.AppendCertsFromPEM(conn.GetCaCert()); !ok {
		return nil, fmt.Errorf("failed to append provided certificate")
	}
	cfg.RootCAs = rootCA
	return cfg, nil
}
