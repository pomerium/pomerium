// Package redis implements a registry in redis.
package redis

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-redis/redis/v8"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/redisutil"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/registry/redis/lua"
	"github.com/pomerium/pomerium/internal/signal"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

const (
	registryKey       = redisutil.KeyPrefix + "registry"
	registryUpdateKey = redisutil.KeyPrefix + "registry_changed_ch"

	pollInterval = time.Second * 30
)

type impl struct {
	cfg *config

	client   redis.UniversalClient
	onChange *signal.Signal

	closeOnce sync.Once
	closed    chan struct{}
}

// New creates a new registry implementation backend by redis.
func New(rawURL string, options ...Option) (registry.Interface, error) {
	cfg := getConfig(options...)

	client, err := redisutil.NewClientFromURL(rawURL, cfg.tls)
	if err != nil {
		return nil, err
	}

	i := &impl{
		cfg:      cfg,
		client:   client,
		onChange: signal.New(),
		closed:   make(chan struct{}),
	}
	go i.listenForChanges(context.Background())
	return i, nil
}

func (i *impl) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	_, err := i.runReport(ctx, req.GetServices())
	if err != nil {
		return nil, err
	}
	return &registrypb.RegisterResponse{
		CallBackAfter: durationpb.New(i.cfg.ttl / 2),
	}, nil
}

func (i *impl) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	all, err := i.runReport(ctx, nil)
	if err != nil {
		return nil, err
	}

	include := map[registrypb.ServiceKind]struct{}{}
	for _, kind := range req.GetKinds() {
		include[kind] = struct{}{}
	}

	filtered := make([]*registrypb.Service, 0, len(all))
	for _, svc := range all {
		if _, ok := include[svc.GetKind()]; !ok {
			continue
		}
		filtered = append(filtered, svc)
	}

	sort.Slice(filtered, func(i, j int) bool {
		{
			iv, jv := filtered[i].GetKind(), filtered[j].GetKind()
			switch {
			case iv < jv:
				return true
			case jv < iv:
				return false
			}
		}

		{
			iv, jv := filtered[i].GetEndpoint(), filtered[j].GetEndpoint()
			switch {
			case iv < jv:
				return true
			case jv < iv:
				return false
			}
		}

		return false
	})

	return &registrypb.ServiceList{
		Services: filtered,
	}, nil
}

func (i *impl) Watch(req *registrypb.ListRequest, stream registrypb.Registry_WatchServer) error {
	// listen for changes
	ch := i.onChange.Bind()
	defer i.onChange.Unbind(ch)

	// force a check periodically
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()

	var prev *registrypb.ServiceList
	for {
		// retrieve the most recent list of services
		lst, err := i.List(stream.Context(), req)
		if err != nil {
			return err
		}

		// only send a new list if something changed
		if !proto.Equal(prev, lst) {
			err = stream.Send(lst)
			if err != nil {
				return err
			}
		}
		prev = lst

		// wait for an update
		select {
		case <-i.closed:
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ch:
		case <-poll.C:
		}
	}
}

func (i *impl) Close() error {
	var err error
	i.closeOnce.Do(func() {
		err = i.client.Close()
		close(i.closed)
	})
	return err
}

func (i *impl) listenForChanges(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-i.closed
		cancel()
	}()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

outer:
	for {
		pubsub := i.client.Subscribe(ctx, registryUpdateKey)
		for {
			msg, err := pubsub.Receive(ctx)
			if err != nil {
				_ = pubsub.Close()
				select {
				case <-ctx.Done():
					return
				case <-time.After(bo.NextBackOff()):
				}
				continue outer
			}
			bo.Reset()

			switch msg.(type) {
			case *redis.Message:
				i.onChange.Broadcast(ctx)
			}
		}
	}
}

func (i *impl) runReport(ctx context.Context, updates []*registrypb.Service) ([]*registrypb.Service, error) {
	args := []interface{}{
		i.cfg.getNow().UnixNano() / int64(time.Millisecond), // current_time
		i.cfg.ttl.Milliseconds(),                            // ttl
	}
	for _, svc := range updates {
		args = append(args, i.getRegistryHashKey(svc))
	}
	res, err := i.client.Eval(ctx, lua.Registry, []string{registryKey, registryUpdateKey}, args...).Result()
	if err != nil {
		return nil, err
	}
	if values, ok := res.([]interface{}); ok {
		var all []*registrypb.Service
		for _, value := range values {
			svc, err := i.getServiceFromRegistryHashKey(fmt.Sprint(value))
			if err != nil {
				log.Warn(ctx).Err(err).Msg("redis: invalid service")
				continue
			}
			all = append(all, svc)
		}
		return all, nil
	}
	return nil, nil
}

func (i *impl) getServiceFromRegistryHashKey(key string) (*registrypb.Service, error) {
	idx := strings.Index(key, "|")
	if idx == -1 {
		return nil, fmt.Errorf("redis: invalid service entry in hash: %s", key)
	}

	svcKindStr := key[:idx]
	svcEndpointStr := key[idx+1:]

	svcKind, ok := registrypb.ServiceKind_value[svcKindStr]
	if !ok {
		return nil, fmt.Errorf("redis: unknown service kind: %s", svcKindStr)
	}

	svc := &registrypb.Service{
		Kind:     registrypb.ServiceKind(svcKind),
		Endpoint: svcEndpointStr,
	}
	return svc, nil
}

func (i *impl) getRegistryHashKey(svc *registrypb.Service) string {
	return svc.GetKind().String() + "|" + svc.GetEndpoint()
}
