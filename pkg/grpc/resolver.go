package grpc

import (
	"strings"
	"sync"

	"google.golang.org/grpc/resolver"
)

func init() {
	resolver.Register(&pomeriumBuilder{})
}

type pomeriumBuilder struct {
}

func (*pomeriumBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	endpoints := strings.Split(target.Endpoint, ",")
	pccd := &pomeriumClientConnData{
		states: make([]resolver.State, len(endpoints)),
	}
	pr := &pomeriumResolver{}
	for i, endpoint := range endpoints {
		subTarget := parseTarget(endpoint)
		b := resolver.Get(subTarget.Scheme)
		pcc := &pomeriumClientConn{
			data:       pccd,
			idx:        i,
			ClientConn: cc,
		}
		r, err := b.Build(subTarget, pcc, opts)
		if err != nil {
			return nil, err
		}
		pr.resolvers = append(pr.resolvers, r)
	}
	return pr, nil
}

func (*pomeriumBuilder) Scheme() string {
	return "pomerium"
}

type pomeriumResolver struct {
	resolvers []resolver.Resolver
}

func (pr *pomeriumResolver) ResolveNow(options resolver.ResolveNowOptions) {
	for _, r := range pr.resolvers {
		r.ResolveNow(options)
	}
}

func (pr *pomeriumResolver) Close() {
	for _, r := range pr.resolvers {
		r.Close()
	}
}

type pomeriumClientConn struct {
	data *pomeriumClientConnData
	idx  int
	resolver.ClientConn
}

func (pcc *pomeriumClientConn) UpdateState(state resolver.State) error {
	return pcc.ClientConn.UpdateState(pcc.data.updateState(pcc.idx, state))
}

type pomeriumClientConnData struct {
	mu     sync.Mutex
	states []resolver.State
}

func (pccd *pomeriumClientConnData) updateState(idx int, state resolver.State) resolver.State {
	pccd.mu.Lock()
	defer pccd.mu.Unlock()

	pccd.states[idx] = state

	merged := resolver.State{}
	for _, s := range pccd.states {
		merged.Addresses = append(merged.Addresses, s.Addresses...)
		merged.ServiceConfig = s.ServiceConfig
		merged.Attributes = s.Attributes
	}
	return merged
}

func parseTarget(raw string) resolver.Target {
	target := resolver.Target{
		Scheme: resolver.GetDefaultScheme(),
	}
	if idx := strings.Index(raw, "://"); idx >= 0 {
		target.Scheme = raw[:idx]
		raw = raw[idx+3:]
	}
	if idx := strings.Index(raw, "/"); idx >= 0 {
		target.Authority = raw[:idx]
		raw = raw[idx+1:]
	}
	target.Endpoint = raw
	return target
}
