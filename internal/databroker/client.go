package databroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// A ClientConnectionManager manages client connections for gRPC.
type ClientConnectionManager struct {
	mu        sync.RWMutex
	sharedKey []byte
	clients   map[string]*grpc.ClientConn
}

// NewClientConnectionManager creates a new ClientConnectionManager.
func NewClientConnectionManager() *ClientConnectionManager {
	return &ClientConnectionManager{
		clients: make(map[string]*grpc.ClientConn),
	}
}

func (mgr *ClientConnectionManager) GetClient(rawURL string) (*grpc.ClientConn, error) {
	mgr.mu.RLock()
	cc, ok := mgr.clients[rawURL]
	mgr.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("databroker/client-connection-manager: no client defined for url")
	}
	return cc, nil
}

func (mgr *ClientConnectionManager) Stop() {
	mgr.mu.Lock()
	for _, cc := range mgr.clients {
		_ = cc.Close()
	}
	clear(mgr.clients)
	mgr.mu.Unlock()
}

func (mgr *ClientConnectionManager) Update(ctx context.Context, cfg *config.Config, rawURLs []string) {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker/client-connection-manager: error getting shared key")
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// if the shared key changed, close all existing connections
	if !bytes.Equal(mgr.sharedKey, sharedKey) {
		for _, cc := range mgr.clients {
			_ = cc.Close()
		}
		clear(mgr.clients)
	}

	for _, rawURL := range rawURLs {
		if _, ok := mgr.clients[rawURL]; ok {
			continue
		}
		cc, err := NewClientConn(mgr.sharedKey, rawURL)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker/client-connection-manager: error creating client connection")
			continue
		}
		mgr.clients[rawURL] = cc
	}
}

func NewClientConn(sharedKey []byte, rawURL string) (*grpc.ClientConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	target := u.Host
	if !strings.Contains(target, ":") {
		if u.Scheme == "http" {
			target += ":80"
		} else {
			target += ":443"
		}
	}

	opts := []grpc.DialOption{
		grpc.WithStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte {
			return sharedKey
		})),
		grpc.WithUnaryInterceptor(grpcutil.WithUnarySignedJWT(func() []byte {
			return sharedKey
		})),
	}
	if u.Scheme == "http" {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})))
	}

	return grpc.NewClient(target, opts...)
}
