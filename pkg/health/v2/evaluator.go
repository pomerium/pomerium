package healthv2

import (
	"context"
	"maps"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

type evaluatorGrpcCC struct {
	shutdown atomic.Bool

	cc grpc.ClientConnInterface
}

func (e *evaluatorGrpcCC) state() (connectivity.State, bool) {
	cc, ok := e.cc.(interface {
		GetState() connectivity.State
	})
	if !ok {
		return connectivity.Ready, false
	}
	return cc.GetState(), true
}

func (e *evaluatorGrpcCC) Initialized(context.Context) (bool, Info) {
	st, ok := e.state()
	if !ok {
		return true, Info{}
	}
	if st == connectivity.Ready || st == connectivity.Idle {
		return true, Info{}
	}
	return false, Info{}
}

func (e *evaluatorGrpcCC) Ready(context.Context) (bool, Info) {
	st, ok := e.state()
	if !ok {
		return true, Info{}
	}
	if st == connectivity.Ready || st == connectivity.Idle {
		return true, Info{}
	}
	return false, Info{}
}

func (e *evaluatorGrpcCC) Healthy(ctx context.Context) (bool, Info) {
	healthy, info := e.healthy(ctx)
	// need to make sure we're not holding open connections forever
	if e.shutdown.Load() {
		return !healthy, info
	}
	return healthy, info
}

func (e *evaluatorGrpcCC) healthy(context.Context) (bool, Info) {
	st, ok := e.state()
	if !ok {
		return true, Info{}
	}
	if st == connectivity.Ready || st == connectivity.Idle {
		return true, Info{}
	}
	return false, Info{}
}

func (e *evaluatorGrpcCC) OnShutdown(context.Context, error) {
	e.shutdown.Store(true)
}

func NewGrpcCCEvaluator(cc grpc.ClientConnInterface) Evaluator {
	return &evaluatorGrpcCC{
		cc: cc,
	}
}

func NewMultiEvaluator(evals ...Evaluator) Evaluator {
	return &compositeEvaluator{
		evaluators: evals,
	}
}

type compositeEvaluator struct {
	evaluators []Evaluator
}

type resultPair struct {
	Result bool
	Info
}

func (e *compositeEvaluator) Initialized(ctx context.Context) (bool, Info) {
	return e.evaluate(ctx, Evaluator.Initialized)
}

func (e *compositeEvaluator) Ready(ctx context.Context) (bool, Info) {
	return e.evaluate(ctx, Evaluator.Ready)
}

func (e *compositeEvaluator) Healthy(ctx context.Context) (bool, Info) {
	return e.evaluate(ctx, Evaluator.Healthy)
}

func (e *compositeEvaluator) OnShutdown(ctx context.Context, shutdownErr error) {
	for _, ev := range e.evaluators {
		ev.OnShutdown(ctx, shutdownErr)
	}
}

func (e *compositeEvaluator) evaluate(ctx context.Context, fn func(Evaluator, context.Context) (bool, Info)) (bool, Info) {
	var wg sync.WaitGroup

	ch := make(chan resultPair, len(e.evaluators))
	for _, ev := range e.evaluators {
		wg.Go(func() {
			ok, info := fn(ev, ctx)
			ch <- resultPair{
				Result: ok,
				Info:   info,
			}
		})
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	ret := []resultPair{}
	for res := range ch {
		ret = append(ret, res)
	}
	return resultPairListToHealth(ret)
}

func resultPairListToHealth(in []resultPair) (bool, Info) {
	mergedResult := true
	mergedInfo := Info{
		Details: map[string]string{},
	}
	reasons := []string{}
	for _, pair := range in {
		if !pair.Result {
			mergedResult = false
		}
		if reason := pair.Info.Reason; reason != "" {
			reasons = append(reasons, pair.Info.Reason)
		}
		maps.Copy(mergedInfo.Details, pair.Info.Details)
	}
	mergedInfo.Reason = strings.Join(reasons, ", ")

	return mergedResult, mergedInfo
}
