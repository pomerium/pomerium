package idpsession

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
)

type benchmarker struct {
	client   databroker.DataBrokerServiceClient
	store    *changeSetStore
	applier  *changeSetApplier
	syncer   *identitySyncer
	sessions []*idpsession.IDPSession
	records  []*databroker.Record

	rng   *rand.Rand
	order []int
}

type nopNotifier struct{}

func (nopNotifier) Reset()   {}
func (nopNotifier) Updated() {}

func newBenchmarker(b *testing.B, numSessions int, numBindings int) *benchmarker {
	b.Helper()

	now := time.Now()
	claims, err := structpb.NewStruct(map[string]any{
		"email":  "bob@example.com",
		"groups": []any{"engineering", "developers"},
	})
	if err != nil {
		b.Fatal(err)
	}

	f := &benchmarker{
		client: dtestutil.NewTestDatabroker(b),
		store:  newChangeSetStore(),
		rng:    rand.New(rand.NewPCG(1, 2)),
	}

	bound := []*databroker.Record{}
	for i := range numSessions {
		idpSessionID := fmt.Sprintf("idp-session-%d", i)
		sess := &idpsession.IDPSession{
			Id: idpSessionID,
			IdToken: &idpsession.IDToken{
				Issuer:    "iss",
				Subject:   idpSessionID,
				ExpiresAt: timestamppb.New(now.Add(time.Hour)),
				IssuedAt:  timestamppb.New(now),
				Raw:       "raw-id-token",
			},
			OauthToken: &idpsession.OAuthToken{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresAt:    timestamppb.New(now.Add(time.Hour)),
				RefreshToken: "refresh",
			},
			State: &idpsession.SessionState{
				State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID,
			},
			Claims: claims,
			UserId: idpSessionID,
			IdpId:  "idp",
		}
		f.sessions = append(f.sessions, sess)
		f.records = append(f.records, databroker.NewRecord(sess))

		u := &user.User{Id: idpSessionID}
		bound = append(bound, databroker.NewRecord(u))
		f.records = append(f.records, databroker.NewRecord(
			idpsession.NewBinding(idpSessionID, idpsession.BindingProtocol_BINDING_PROTOCOL_UNKNOWN, u, map[string]string{}),
		))

		for n := range numBindings - 1 {
			s := &session.Session{
				Id:        fmt.Sprintf("%s-session-%d", idpSessionID, n),
				UserId:    idpSessionID,
				ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			}
			bound = append(bound, databroker.NewRecord(s))
			f.records = append(f.records, databroker.NewRecord(
				idpsession.NewBinding(idpSessionID, idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, s, map[string]string{}),
			))
		}
	}

	if err := databroker.PutMulti(b.Context(), f.client, bound...); err != nil {
		b.Fatal(err)
	}
	if err := databroker.PutMulti(b.Context(), f.client, f.records...); err != nil {
		b.Fatal(err)
	}

	clientB := databroker.NewStaticClientGetter(f.client)
	f.applier = newChangeSetApplier(clientB, f.store)
	// tokens expire an hour out and user info refreshes hourly, so no scheduler
	// fires during a run.
	refreshMgr := newRefreshManager(RefreshConfig{
		SessionRefreshGracePeriod:     time.Minute,
		SessionRefreshCoolOffDuration: 10 * time.Second,
		UpdateUserInfoInterval:        time.Hour,
		Now:                           time.Now,
		EventMgr:                      events.New(),
		TracerProvider:                noop.TracerProvider{},
		GetAuthenticator: func(context.Context, string) (identity.Authenticator, error) {
			return &mockAuthenticator{}, nil
		},
	}, f.store, clientB)
	b.Cleanup(refreshMgr.Close)

	f.order = make([]int, len(f.sessions))
	for i := range f.order {
		f.order[i] = i
	}

	f.syncer = newIdentitySyncer(clientB, f.store, f.applier, refreshMgr, nopNotifier{}, time.Now)
	return f
}

// randomSessions returns n distinct sessions, or every session if n exceeds how
// many there are. It is a partial Fisher-Yates over a retained index slice, so
// it costs O(n) and allocates only the result.
func (f *benchmarker) randomSessions(n int) []*idpsession.IDPSession {
	n = min(n, len(f.sessions))
	picked := make([]*idpsession.IDPSession, n)
	for i := range n {
		j := i + f.rng.IntN(len(f.order)-i)
		f.order[i], f.order[j] = f.order[j], f.order[i]
		picked[i] = f.sessions[f.order[i]]
	}
	return picked
}

func BenchmarkSyncerUpdateRecordsIncremental(b *testing.B) {
	log.SetLevel(zerolog.Disabled)
	numSessions := 1000
	numBindings := 50
	f := newBenchmarker(b, numSessions, numBindings)

	cpuFile, err := os.Create("cpu_incremental.pprof")
	if err != nil {
		b.Fatalf("creating cpu profile : %s", err)
	}
	defer cpuFile.Close()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		b.Fatalf("starting pprof : %s", err)
	}
	defer pprof.StopCPUProfile()

	b.Logf("sessions : %d, bindings : %d ", numSessions, numBindings)
	numPerLoop := 50
	b.StartTimer()
	defer b.StopTimer()
	for i := 0; i+numPerLoop < len(f.records); i += numPerLoop {
		f.syncer.UpdateRecords(b.Context(), 1, f.records[i:i+numPerLoop])
		// absurd cap in the future to make sure all changes are synced.
		f.applier.ReconcileAtLocked(b.Context(), time.Now().Add(time.Hour*24*365))
	}
}

func BenchmarkSyncerUpdateRecordsBatch(b *testing.B) {
	log.SetLevel(zerolog.Disabled)
	numSessions := 1000
	numBindings := 50
	f := newBenchmarker(b, numSessions, numBindings)

	cpuFile, err := os.Create("cpu_batch.pprof")
	if err != nil {
		b.Fatalf("creating cpu profile : %s", err)
	}
	defer cpuFile.Close()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		b.Fatalf("starting pprof : %s", err)
	}
	defer pprof.StopCPUProfile()

	b.Logf("sessions : %d, bindings : %d ", numSessions, numBindings)
	b.StartTimer()
	defer b.StopTimer()

	f.syncer.UpdateRecords(b.Context(), 1, f.records)
	// absurd cap in the future to make sure all changes are synced.
	f.applier.ReconcileAtLocked(b.Context(), time.Now().Add(time.Hour*24*365))
}

func BenchmarkSyncerPropagateN(b *testing.B) {
	log.SetLevel(zerolog.Disabled)
	f := newBenchmarker(b, 1000, 50)

	f.syncer.UpdateRecords(b.Context(), 1, f.records)

	// change n idpsessions
	propagateToN := 50
	b.Logf("loop changes %d idpsession to propagate & reconcile", propagateToN)
	cpuFile, err := os.Create("cpu_propagate.pprof")
	if err != nil {
		b.Fatalf("creating cpu profile : %s", err)
	}
	defer cpuFile.Close()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		b.Fatalf("starting pprof : %s", err)
	}
	defer pprof.StopCPUProfile()

	for b.Loop() {
		at := time.Now()
		for _, sess := range f.randomSessions(propagateToN) {
			f.applier.onUpdateIDPSession(sess, at)
		}
		if err := f.applier.ReconcileAtLocked(b.Context(), at.Add(time.Hour*24*365)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSyncerPropagateAll(b *testing.B) {
	log.SetLevel(zerolog.Disabled)
	f := newBenchmarker(b, 1000, 50)
	f.syncer.UpdateRecords(b.Context(), 1, f.records)
	cpuFile, err := os.Create("cpu_propagate_all.pprof")
	if err != nil {
		b.Fatalf("creating cpu profile : %s", err)
	}
	defer cpuFile.Close()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		b.Fatalf("starting pprof : %s", err)
	}
	defer pprof.StopCPUProfile()

	for b.Loop() {
		at := time.Now()
		for _, sess := range f.sessions {
			f.applier.onUpdateIDPSession(sess, at)
		}
		if err := f.applier.ReconcileAtLocked(b.Context(), at.Add(time.Hour*24*365)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSyncerPropagateIdle(b *testing.B) {
	log.SetLevel(zerolog.Disabled)
	f := newBenchmarker(b, 1000, 50)
	at := time.Now()
	f.syncer.UpdateRecords(b.Context(), 1, f.records)

	if err := f.applier.ReconcileAtLocked(b.Context(), at); err != nil {
		b.Fatal(err)
	}

	cpuFile, err := os.Create("cpu_propagate_idle.pprof")
	if err != nil {
		b.Fatalf("creating cpu profile : %s", err)
	}
	defer cpuFile.Close()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		b.Fatalf("starting pprof : %s", err)
	}
	defer pprof.StopCPUProfile()

	for b.Loop() {
		if err := f.applier.ReconcileAtLocked(b.Context(), at); err != nil {
			b.Fatal(err)
		}
	}
}

// TODO : revocation benchmarks
