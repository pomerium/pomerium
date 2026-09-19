package authenticateflow

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestSessionToBindingData_AgenticPropagatesTransientReadFailure pins that only
// a MISSING agentic session takes the binding-only fallback.
//
// The fallback exists because an expired run's session is deleted before its
// binding is revoked, so NotFound is an ordinary state with a truthful answer:
// there is no expiry left to report. Every other failure is a statement about
// the databroker, not about the run — answering one with the fallback invents a
// row that says the run lasts "Until revoked or IDP expires" and hides its
// executor claims, which is worse than reporting the failure.
func TestSessionToBindingData_AgenticPropagatesTransientReadFailure(t *testing.T) {
	t.Parallel()

	for _, code := range []codes.Code{
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.Canceled,
		codes.Internal,
	} {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
			client.EXPECT().Get(gomock.Any(), gomock.Any()).
				Return(nil, status.Error(code, "induced"))

			s := &Stateful{dataBrokerClient: client}
			binding := &idpsession.Binding{
				Id:       "agentic-run-1",
				TypeUrl:  protoutil.GetTypeURL(new(session.Session)),
				Protocol: idpsession.BindingProtocol_BINDING_PROTOCOL_AGENTIC,
				Details:  map[string]string{agentic.DetailRunID: "run-1"},
			}

			_, err := s.sessionToBindingData(t.Context(), binding, url.URL{})
			require.Error(t, err, "%s is an infrastructure failure, not a vanished run", code)
			assert.Equal(t, code, status.Code(err),
				"the original status must survive so the caller can tell what failed")
		})
	}
}

// TestSessionToBindingData_AgenticKeepsFallbackOnNotFound is the other half:
// the case the fallback was actually built for must keep working.
func TestSessionToBindingData_AgenticKeepsFallbackOnNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	client.EXPECT().Get(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.NotFound, "no such session"))

	s := &Stateful{dataBrokerClient: client}
	binding := &idpsession.Binding{
		Id:       "agentic-run-1",
		TypeUrl:  protoutil.GetTypeURL(new(session.Session)),
		Protocol: idpsession.BindingProtocol_BINDING_PROTOCOL_AGENTIC,
		Details:  map[string]string{agentic.DetailRunID: "run-1"},
	}

	got, err := s.sessionToBindingData(t.Context(), binding, url.URL{})
	require.NoError(t, err, "an expired run's session is legitimately gone")
	require.NotNil(t, got.DetailsAgentic)
	assert.Equal(t, "run-1", got.DetailsAgentic.RunID)
}
