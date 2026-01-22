// Package main contains the xdserr cmd
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	_ "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tests/xdserr"
	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func main() {
	ctx := context.Background()

	graceful := flag.Bool("graceful", false, "gracefully grow")
	domain := flag.String("domain", "localhost.pomerium.io", "domain to create routes in")
	routes := flag.Int("routes", 100, "number of routes")
	cycles := flag.Int("cycles", 1, "number of cycles")
	change := flag.Int("change", 1, "number of change per cycle")
	addr := flag.String("db-url", "http://localhost:5443", "databroker url")
	key := flag.String("key", "", "databroker connection key")
	to := flag.String("to", "", "route To url")

	flag.Parse()

	toURL, err := url.Parse(*to)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg(*to)
		return
	}

	eg, ctx := errgroup.WithContext(ctx)
	conn, err := grpcConn(ctx, *addr, *key)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker grpc conn")
		return
	}
	defer conn.Close()

	if *to == "" {
		*to, err = xdserr.RunEcho(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("echo server")
			return
		}
	}
	log.Ctx(ctx).Info().Str("url", *to).Msg("echo server")

	eg.Go(func() error {
		return run(ctx, conn, *toURL, *domain, opts{
			graceful: *graceful,
			nRoutes:  *routes,
			nIter:    *cycles,
			nMod:     *change,
		})
	})
	if err := eg.Wait(); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("altering config")
	}
}

type opts struct {
	nRoutes, nIter, nMod int
	graceful             bool
}

func run(ctx context.Context, conn *grpc.ClientConn, to url.URL, domain string, o opts) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dbc := databroker.NewDataBrokerServiceClient(conn)
	cfg := new(config.Config)

	for i := 0; i < o.nRoutes; i++ {
		cfg.Routes = append(cfg.Routes, makeRoute(domain, to))
	}

	rand.Seed(time.Now().Unix())

	changed := make([]int, o.nMod)
	for i := 0; i < o.nIter; i++ {
		for j := 0; j < o.nMod; j++ {
			//nolint: gosec
			idx := rand.Intn(o.nRoutes)
			changed[j] = idx
			cfg.Routes[idx] = makeRoute(domain, to)
		}
		log.Ctx(ctx).Info().Ints("changed", changed).Msg("changed")
		if err := saveAndLogConfig(ctx, dbc, cfg, o.graceful); err != nil {
			return err
		}
	}

	if !o.graceful {
		return waitHealthy(ctx, httpClient, cfg.Routes)
	}

	return nil
}

func grpcConn(ctx context.Context, addr, keyTxt string) (*grpc.ClientConn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(keyTxt)
	if err != nil {
		return nil, err
	}
	fmt.Println(keyTxt)
	return grpcutil.NewGRPCClientConn(ctx, &grpcutil.Options{
		Address:            u,
		InsecureSkipVerify: true,
		SignedJWTKey:       key,
	})
}

func makeRoute(domain string, to url.URL) *config.Route {
	id := fmt.Sprintf("r-%s", uuid.NewString())
	return &config.Route{
		Name:                             &id,
		From:                             fmt.Sprintf("https://%s.%s", id, domain),
		Path:                             "/",
		PrefixRewrite:                    to.Path,
		To:                               []string{to.String()},
		AllowPublicUnauthenticatedAccess: true,
	}
}

func saveAndLogConfig(ctx context.Context, client databroker.DataBrokerServiceClient, cfg *config.Config, graceful bool) error {
	if err := saveConfig(ctx, client, cfg); err != nil {
		return err
	}

	if graceful {
		return waitHealthy(ctx, httpClient, cfg.Routes)
	}

	return nil
}

func waitHealthy(ctx context.Context, _ *http.Client, routes []*config.Route) error {
	now := time.Now()
	if err := xdserr.WaitForHealthy(ctx, httpClient, routes); err != nil {
		return err
	}

	log.Ctx(ctx).Info().
		Int("routes", len(routes)).
		Str("elapsed", time.Since(now).String()).
		Msg("ok")

	return nil
}

func saveConfig(ctx context.Context, client databroker.DataBrokerServiceClient, cfg *config.Config) error {
	data := protoutil.NewAny(cfg)
	r, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.GetTypeUrl(),
			Id:   "test_config",
			Data: data,
		}},
	})
	if err != nil {
		return err
	}
	log.Ctx(ctx).Info().Uint64("version", r.GetRecord().GetVersion()).Msg("set config")
	return nil
}
