package authorize

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh"
)

func TestEvaluateUpstreamTunnel(t *testing.T) {
	t.Parallel()

	route1 := config.Policy{
		From: "https://tunnel-1.example.com",
		To: config.WeightedURLs{{
			URL: url.URL{Scheme: "http", Host: "localhost:8001"},
		}},
		UpstreamTunnel: &config.UpstreamTunnel{
			// no policy specified
		},
	}
	route2 := config.Policy{
		From: "https://tunnel-2.example.com",
		To: config.WeightedURLs{{
			URL: url.URL{Scheme: "http", Host: "localhost:8002"},
		}},
		UpstreamTunnel: &config.UpstreamTunnel{
			SSHPolicy: parsePPL(t, `
- allow:
    and:
      - email:
          is: user@example.com
`),
		},
	}

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.Routes = []config.Policy{route1, route2}
	a, err := New(t.Context(), cfg)
	require.NoError(t, err)

	db := testutil.NewTestDatabroker(t)
	putRecords(t, db,
		&session.Session{
			Id:     "SESSION-1",
			UserId: "USER-1",
		},
		&user.User{
			Id:    "USER-1",
			Email: "user@example.com",
		})
	state := a.state.Load()
	state.dataBrokerClient = db
	a.state.Store(state)

	res, err := a.EvaluateUpstreamTunnel(t.Context(), ssh.AuthRequest{
		SessionID:        "SESSION-1",
		SessionBindingID: "SB-1",
	}, &route1)
	require.NoError(t, err)
	assert.Equal(t, evaluator.NewRuleResult(false), res.Allow)
	assert.Equal(t, evaluator.NewRuleResult(false), res.Deny)

	res, err = a.EvaluateUpstreamTunnel(t.Context(), ssh.AuthRequest{
		SessionID:        "SESSION-1",
		SessionBindingID: "SB-1",
	}, &route2)
	require.NoError(t, err)
	assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonEmailOK), res.Allow)
	assert.Equal(t, evaluator.NewRuleResult(false), res.Deny)
}

type recordMessage interface {
	proto.Message
	GetId() string
}

func putRecords(t *testing.T, db databroker.DataBrokerServiceClient, records ...recordMessage) {
	var req databroker.PutRequest
	for _, r := range records {
		data := protoutil.NewAny(r)
		req.Records = append(req.Records, &databroker.Record{
			Type: data.GetTypeUrl(),
			Id:   r.GetId(),
			Data: data,
		})
	}
	_, err := db.Put(t.Context(), &req)
	require.NoError(t, err)
}

func parsePPL(t *testing.T, ppl string) *config.PPLPolicy {
	p, err := parser.New().ParseYAML(strings.NewReader(ppl))
	require.NoError(t, err)
	return &config.PPLPolicy{
		Policy: p,
	}
}
