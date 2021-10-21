// Package xdserr to load test configuration updates
package xdserr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	adminv3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
)

type cfgDump struct {
	Configs []json.RawMessage `json:"configs"`
}

// DumpConfig acquires current config from admin endpoint
func DumpConfig(ctx context.Context, adminURL string) (*adminv3.RoutesConfigDump, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/config_dump"

	req := http.Request{
		Method: http.MethodGet,
		URL:    u,
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	cfg := cfgDump{}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	any, _ := anypb.New(&emptypb.Empty{})
	fmt.Println(protojson.Format(any))
	opts := &protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}
	for i, data := range cfg.Configs {
		any := new(anypb.Any)
		if err = opts.Unmarshal(data, any); err != nil {
			log.Error(ctx).Err(err).Int("config", i).
				//RawJSON("data", data).
				Msg("decode")
		} else {
			log.Info(ctx).Msg(any.TypeUrl)
		}
	}
	return nil, err
}
