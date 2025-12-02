package sshtest

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
	mock_ssh "github.com/pomerium/pomerium/pkg/ssh/mock"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type OpOrder int

const (
	AddStream OpOrder = iota
	OnStreamAuthenticated
	OnSessionCreated
	ProcessConfigUpdate
)

type PolicyIndexConformanceSuite[T ssh.PolicyIndexer] struct {
	suite.Suite

	index  T
	ctrl   *gomock.Controller
	eval   *mock_ssh.MockSSHEvaluator
	funcs  TestFuncs[T]
	order  []OpOrder
	wait   chan struct{}
	cancel context.CancelFunc

	expectedLastKnownStreams  int
	expectedLastKnownSessions int
}

func (s *PolicyIndexConformanceSuite[T]) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.eval = mock_ssh.NewMockSSHEvaluator(s.ctrl)
	s.index = s.funcs.Create(s.eval)
	s.wait = make(chan struct{})
	var ctx context.Context
	ctx, s.cancel = context.WithCancel(s.T().Context())
	s.expectedLastKnownStreams = 0
	s.expectedLastKnownSessions = 0

	go func() {
		defer close(s.wait)
		s.funcs.Run(ctx, s.index)
	}()
}

func (s *PolicyIndexConformanceSuite[T]) SetupSubTest() {
	if s.wait != nil {
		s.TearDownTest()
	}
	s.SetupTest()
}

func (s *PolicyIndexConformanceSuite[T]) TearDownTest() {
	if s.wait == nil {
		return
	}
	s.cancel()
	<-s.wait
	s.wait = nil
	if !s.T().Failed() {
		s.Equal(s.expectedLastKnownStreams, s.funcs.NumKnownStreams(s.index))
		s.Equal(s.expectedLastKnownSessions, s.funcs.NumKnownSessions(s.index))
	}
}

func (s *PolicyIndexConformanceSuite[T]) TearDownSubTest() {
	s.TearDownTest()
}

type TestFuncs[T ssh.PolicyIndexer] struct {
	Create           func(ssh.SSHEvaluator) T
	Run              func(ctx context.Context, t T)
	NumKnownStreams  func(t T) int
	NumKnownSessions func(t T) int
}

func NewPolicyIndexConformanceSuite[T ssh.PolicyIndexer](funcs TestFuncs[T]) *PolicyIndexConformanceSuite[T] {
	return &PolicyIndexConformanceSuite[T]{
		funcs: funcs,
	}
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdateStaticPorts_UnauthenticatedStreams() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"

	// Nothing should be called until the streams have been authenticated
	s.index.AddStream(1, mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl))
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(2, mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl))
	cfg.Options.SSHAddr = ""
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(3, mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl))
	cfg.Options.SSHAddr = "localhost:2200"
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(4, mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl))

	s.expectedLastKnownStreams = 4
	s.expectedLastKnownSessions = 0
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdateStaticPorts_AuthenticatedStreams() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	{
		call1 := sub1.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1)
		call2 := sub1.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443})).
			Times(1).After(call1)
		sub1.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1).After(call2)
	}
	sub2 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	{
		call1 := sub2.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1)
		call2 := sub2.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443})).
			Times(1).After(call1)
		sub2.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1).After(call2)
	}
	sub3 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	{
		call1 := sub3.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443})).
			Times(1)
		sub3.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1).After(call1)
	}
	sub4 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	{
		sub4.EXPECT().
			UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22})).
			Times(1)
	}

	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, ssh.AuthRequest{SessionID: "session1"})
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(2, sub2)
	s.index.OnStreamAuthenticated(2, ssh.AuthRequest{SessionID: "session2"})
	cfg.Options.SSHAddr = ""
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(3, sub3)
	s.index.OnStreamAuthenticated(3, ssh.AuthRequest{SessionID: "session3"})
	cfg.Options.SSHAddr = "localhost:2200"
	s.index.ProcessConfigUpdate(cfg.Clone())
	s.index.AddStream(4, sub4)
	s.index.OnStreamAuthenticated(4, ssh.AuthRequest{SessionID: "session4"})

	s.expectedLastKnownStreams = 4
	s.expectedLastKnownSessions = 4
}

func parseWeightedUrls(urls ...string) config.WeightedURLs {
	r, err := config.ParseWeightedUrls(urls...)
	if err != nil {
		panic(err)
	}
	return r
}

var samplePolicies = []config.Policy{
	{
		Name:           "http1",
		From:           "https://route1",
		To:             parseWeightedUrls("http://to1"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
	{
		Name:           "http2",
		From:           "https://route2",
		To:             parseWeightedUrls("http://to2"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
	{
		Name:           "http3",
		From:           "https://route3",
		To:             parseWeightedUrls("http://to3"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
}

var samplePolicies2 = []config.Policy{
	{
		Name:           "http4",
		From:           "https://route4",
		To:             parseWeightedUrls("http://to4"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
	{
		Name:           "http5",
		From:           "https://route5",
		To:             parseWeightedUrls("http://to5"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
	{
		Name:           "http6",
		From:           "https://route6",
		To:             parseWeightedUrls("http://to6"),
		UpstreamTunnel: &config.UpstreamTunnel{},
	},
}

var orders = [][]OpOrder{
	0: {AddStream, OnStreamAuthenticated, OnSessionCreated, ProcessConfigUpdate},
	1: {AddStream, OnStreamAuthenticated, ProcessConfigUpdate, OnSessionCreated},
	2: {AddStream, OnSessionCreated, OnStreamAuthenticated, ProcessConfigUpdate},
	3: {AddStream, OnSessionCreated, ProcessConfigUpdate, OnStreamAuthenticated},
	4: {AddStream, ProcessConfigUpdate, OnStreamAuthenticated, OnSessionCreated},
	5: {AddStream, ProcessConfigUpdate, OnSessionCreated, OnStreamAuthenticated},

	6:  {OnStreamAuthenticated, AddStream, OnSessionCreated, ProcessConfigUpdate},
	7:  {OnStreamAuthenticated, AddStream, ProcessConfigUpdate, OnSessionCreated},
	8:  {OnStreamAuthenticated, OnSessionCreated, AddStream, ProcessConfigUpdate},
	9:  {OnStreamAuthenticated, OnSessionCreated, ProcessConfigUpdate, AddStream},
	10: {OnStreamAuthenticated, ProcessConfigUpdate, AddStream, OnSessionCreated},
	11: {OnStreamAuthenticated, ProcessConfigUpdate, OnSessionCreated, AddStream},

	12: {OnSessionCreated, AddStream, OnStreamAuthenticated, ProcessConfigUpdate},
	13: {OnSessionCreated, AddStream, ProcessConfigUpdate, OnStreamAuthenticated},
	14: {OnSessionCreated, OnStreamAuthenticated, AddStream, ProcessConfigUpdate},
	15: {OnSessionCreated, OnStreamAuthenticated, ProcessConfigUpdate, AddStream},
	16: {OnSessionCreated, ProcessConfigUpdate, AddStream, OnStreamAuthenticated},
	17: {OnSessionCreated, ProcessConfigUpdate, OnStreamAuthenticated, AddStream},

	18: {ProcessConfigUpdate, AddStream, OnStreamAuthenticated, OnSessionCreated},
	19: {ProcessConfigUpdate, AddStream, OnSessionCreated, OnStreamAuthenticated},
	20: {ProcessConfigUpdate, OnStreamAuthenticated, AddStream, OnSessionCreated},
	21: {ProcessConfigUpdate, OnStreamAuthenticated, OnSessionCreated, AddStream},
	22: {ProcessConfigUpdate, OnSessionCreated, AddStream, OnStreamAuthenticated},
	23: {ProcessConfigUpdate, OnSessionCreated, OnStreamAuthenticated, AddStream},
}

func makeRouteInfoFromPolicy(p *config.Policy) portforward.RouteInfo {
	return portforward.RouteInfo{
		From:      p.From,
		To:        p.To,
		Hostname:  strings.TrimPrefix(p.From, "https://"),
		Port:      443,
		ClusterID: envoyconfig.GetClusterID(p),
	}
}

var allow = &evaluator.Result{
	Allow: evaluator.NewRuleResult(true),
	Deny:  evaluator.NewRuleResult(false),
}

var deny = &evaluator.Result{
	Allow: evaluator.NewRuleResult(false),
	Deny:  evaluator.NewRuleResult(true),
}

type addStreamArgs struct {
	streamID uint64
	sub      ssh.PolicyIndexSubscriber
}
type onStreamAuthenticatedArgs struct {
	streamID uint64
	req      ssh.AuthRequest
}

type onSessionCreatedArgs struct {
	session *session.Session
}

type processConfigUpdateArgs struct {
	config *config.Config
}

func (s *PolicyIndexConformanceSuite[T]) runPermutation(
	addStreamArgs addStreamArgs,
	onStreamAuthenticatedArgs onStreamAuthenticatedArgs,
	onSessionCreatedArgs onSessionCreatedArgs,
	processConfigUpdateArgs processConfigUpdateArgs,
	beforeLastOp func(),
) {
	for i, op := range s.order {
		if i == len(s.order)-1 {
			beforeLastOp()
		}
		switch op {
		case AddStream:
			s.index.AddStream(addStreamArgs.streamID, addStreamArgs.sub)
		case OnSessionCreated:
			s.index.OnSessionCreated(onSessionCreatedArgs.session)
		case OnStreamAuthenticated:
			s.index.OnStreamAuthenticated(onStreamAuthenticatedArgs.streamID, onStreamAuthenticatedArgs.req)
		case ProcessConfigUpdate:
			s.index.ProcessConfigUpdate(processConfigUpdateArgs.config)
		default:
			panic(fmt.Sprintf("unexpected ssh_test.OpOrder: %#v", op))
		}
	}
}

func (s *PolicyIndexConformanceSuite[T]) testEachPermutation(f func()) {
	for i, order := range orders {
		s.Run(fmt.Sprintf("Order %d", i), func() {
			s.order = order
			f()
		})
	}
}

func (s *PolicyIndexConformanceSuite[T]) TestAllowAll() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[0])).
			Return(allow, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[1])).
			Return(allow, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[2])).
			Return(allow, nil)

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{&cfg},
			func() {
				sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
				}))
			},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestAllowSome() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[0])).
			Return(allow, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[1])).
			Return(allow, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[2])).
			Return(deny, nil)

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{&cfg},
			func() {
				sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
				}))
			},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestAllowNone() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[0])).
			Return(deny, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[1])).
			Return(deny, nil)
		s.eval.EXPECT().
			EvaluateUpstreamTunnel(gomock.Any(), gomock.Eq(sessionAuthReq1), gomock.Eq(&cfg.Options.Policies[2])).
			Return(deny, nil)

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{&cfg},
			func() {},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdateEvalResult() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies
		cfg2 := cfg.Clone()
		cfg2.Options.Policies = slices.Clone(cfg.Options.Policies)

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
				switch p {
				case &cfg.Options.Policies[0], &cfg.Options.Policies[1], &cfg.Options.Policies[2]:
					return deny, nil
				case &cfg2.Options.Policies[0], &cfg2.Options.Policies[1], &cfg2.Options.Policies[2]:
					return allow, nil
				default:
					panic("bug: unknown policy")
				}
			}).AnyTimes()

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.index.ProcessConfigUpdate(&cfg)

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{cfg2},
			func() {
				sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[2]),
				}))
			},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdatePoliciesDenyThenAllow() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies
		cfg2 := cfg.Clone()
		cfg2.Options.Policies = samplePolicies2

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
				switch p {
				case &cfg.Options.Policies[0], &cfg.Options.Policies[1], &cfg.Options.Policies[2]:
					return deny, nil
				case &cfg2.Options.Policies[0], &cfg2.Options.Policies[1], &cfg2.Options.Policies[2]:
					return allow, nil
				default:
					panic("bug: unknown policy")
				}
			}).AnyTimes()

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.index.ProcessConfigUpdate(&cfg)

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{cfg2},
			func() {
				sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[2]),
				}))
			},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdatePoliciesAllowThenDeny() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies
		cfg2 := cfg.Clone()
		cfg2.Options.Policies = samplePolicies2

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
				switch p {
				case &cfg.Options.Policies[0], &cfg.Options.Policies[1], &cfg.Options.Policies[2]:
					return allow, nil
				case &cfg2.Options.Policies[0], &cfg2.Options.Policies[1], &cfg2.Options.Policies[2]:
					return deny, nil
				default:
					panic("bug: unknown policy")
				}
			}).AnyTimes()

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.index.ProcessConfigUpdate(&cfg)

		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{cfg2},
			func() {
				if slices.Index(s.order, ProcessConfigUpdate) == 3 {
					sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
						makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
						makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
						makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
					}))
					sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{}))
				}
			},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestUpdatePoliciesAllowThenAllow() {
	s.testEachPermutation(func() {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Policies = samplePolicies
		cfg2 := cfg.Clone()
		cfg2.Options.Policies = samplePolicies2

		sessionAuthReq1 := ssh.AuthRequest{
			SessionID: "session1",
		}

		s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(allow, nil).
			AnyTimes()

		sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
		sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

		s.index.ProcessConfigUpdate(&cfg)
		if slices.Index(s.order, ProcessConfigUpdate) == 3 {
			call1 := sub1.EXPECT().
				UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
				})).
				Times(1)
			sub1.EXPECT().
				UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[2]),
				})).
				After(call1)
		} else {
			sub1.EXPECT().
				UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[0]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[1]),
					makeRouteInfoFromPolicy(&cfg2.Options.Policies[2]),
				}))
		}
		s.runPermutation(
			addStreamArgs{1, sub1},
			onStreamAuthenticatedArgs{1, sessionAuthReq1},
			onSessionCreatedArgs{&session.Session{Id: "session1"}},
			processConfigUpdateArgs{cfg2},
			func() {},
		)

		s.expectedLastKnownStreams = 1
		s.expectedLastKnownSessions = 1
	})
}

func (s *PolicyIndexConformanceSuite[T]) TestMultipleStreamsWithSameSession() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(allow, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub2 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub2.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.AddStream(2, sub2)
	sub2.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnStreamAuthenticated(2, sessionAuthReq1)

	s.expectedLastKnownStreams = 2
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestStreamReconnectSameSession() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(allow, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	s.index.RemoveStream(1)

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))
	s.index.AddStream(2, sub1)
	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnStreamAuthenticated(2, sessionAuthReq1)

	s.expectedLastKnownStreams = 1
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestPolicyChangeBeforeReconnect() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies
	cfg2 := cfg.Clone()
	cfg2.Options.Policies = samplePolicies2

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
			switch p {
			case &cfg.Options.Policies[0], &cfg.Options.Policies[1], &cfg.Options.Policies[2]:
				return allow, nil
			case &cfg2.Options.Policies[0], &cfg2.Options.Policies[1], &cfg2.Options.Policies[2]:
				return deny, nil
			default:
				panic("bug: unknown policy")
			}
		}).AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	s.index.RemoveStream(1)

	// update the policy to make the session no longer authorized
	s.index.ProcessConfigUpdate(cfg2)

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))
	// no callbacks
	s.index.AddStream(2, sub1)
	s.index.OnStreamAuthenticated(2, sessionAuthReq1)

	s.expectedLastKnownStreams = 1
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestPolicyChangeBeforeReconnectWithOtherStreamsStillConnected() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies
	cfg2 := cfg.Clone()
	cfg2.Options.Policies = samplePolicies2

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
			switch p {
			case &cfg.Options.Policies[0], &cfg.Options.Policies[1], &cfg.Options.Policies[2]:
				return allow, nil
			case &cfg2.Options.Policies[0], &cfg2.Options.Policies[1], &cfg2.Options.Policies[2]:
				return deny, nil
			default:
				panic("bug: unknown policy")
			}
		}).AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub2 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub2.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.AddStream(2, sub2)
	sub2.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnStreamAuthenticated(2, sessionAuthReq1)

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	s.index.RemoveStream(1)

	// Update the policy to make the session no longer authorized. The other
	// stream currently connected gets the callback immediately, and the
	// reconnected stream should get no callback.
	sub2.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{}))
	s.index.ProcessConfigUpdate(cfg2)

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))
	s.index.AddStream(3, sub1) // note the stream id must be different
	s.index.OnStreamAuthenticated(3, sessionAuthReq1)

	s.expectedLastKnownStreams = 2
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestSessionDeletedWhileConnected() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(allow, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	s.index.OnSessionDeleted("session1")

	s.expectedLastKnownStreams = 1
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestSessionDeletedThenStreamsRemoved() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(allow, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub2 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub2.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))
	s.index.AddStream(2, sub2)
	sub2.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnStreamAuthenticated(2, sessionAuthReq1)

	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	sub2.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))

	s.index.OnSessionDeleted("session1")

	// Now remove each stream
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	s.index.RemoveStream(1)
	sub2.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	s.index.RemoveStream(2)

	s.expectedLastKnownStreams = 0
	s.expectedLastKnownSessions = 0
}

func (s *PolicyIndexConformanceSuite[T]) TestSessionDeletedWhileConnectedButNoAuthorizedRoutes() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(deny, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	s.index.OnSessionCreated(&session.Session{Id: "session1"})
	s.index.OnSessionDeleted("session1")

	s.expectedLastKnownStreams = 1
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestSessionDeletedWhileDisconnected() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sessionAuthReq1 := ssh.AuthRequest{
		SessionID: "session1",
	}

	s.eval.EXPECT().EvaluateUpstreamTunnel(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(allow, nil).
		AnyTimes()

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	sub1.EXPECT().
		UpdateAuthorizedRoutes(gomock.Eq([]portforward.RouteInfo{
			makeRouteInfoFromPolicy(&cfg.Options.Policies[0]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[1]),
			makeRouteInfoFromPolicy(&cfg.Options.Policies[2]),
		}))
	s.index.OnSessionCreated(&session.Session{Id: "session1"})

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	sub1.EXPECT().UpdateAuthorizedRoutes(gomock.Len(0))
	s.index.RemoveStream(1)

	// delete the session while no streams are attached
	s.index.OnSessionDeleted("session1")

	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))
	s.index.AddStream(1, sub1)

	// This would only actually happen if there is some lag in the session syncer,
	// meaning we will likely get an OnSessionCreated event very soon after, but
	// the indexer should properly handle this and wait to fire the callbacks
	// until that happens.
	s.index.OnStreamAuthenticated(1, sessionAuthReq1)

	s.expectedLastKnownStreams = 1
	s.expectedLastKnownSessions = 1
}

func (s *PolicyIndexConformanceSuite[T]) TestCreateDeleteUnauthenticatedStream() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.RemoveStream(1)
}

func (s *PolicyIndexConformanceSuite[T]) TestDeleteAuthenticatedStreamBeforeSessionCreated() {
	cfg := config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = samplePolicies

	sub1 := mock_ssh.NewMockPolicyIndexSubscriber(s.ctrl)
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Eq([]uint{443, 22}))

	s.index.ProcessConfigUpdate(&cfg)
	s.index.AddStream(1, sub1)
	s.index.OnStreamAuthenticated(1, ssh.AuthRequest{SessionID: "session1"})
	sub1.EXPECT().UpdateEnabledStaticPorts(gomock.Len(0))
	s.index.RemoveStream(1)
}
