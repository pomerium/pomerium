package idpsession

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcode "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	sliceutil "github.com/pomerium/pomerium/pkg/slices"
)

type ID struct {
	UserID string
	IdpID  string
}

func (i ID) Validate() error {
	if i.UserID == "" {
		return fmt.Errorf("validate: empty user ID")
	}
	if i.IdpID == "" {
		return fmt.Errorf("validate: empty IDP ID")
	}
	return nil
}

func (i ID) RecordID() string {
	return fmt.Sprintf("idpsess.%s.%s", i.IdpID, i.UserID)
}

type authenticatorGetter func(ctx context.Context, idpID string) (identity.Authenticator, error)

type Manager interface {
	Create(ctx context.Context, id ID, token *oauth2.Token, rawIDToken string) error
	Refresh(ctx context.Context, id ID, state identity.State) (*oauth2.Token, error)
	Revoke(ctx context.Context, id ID) error
}

type DistributedManager struct {
	getAuthenticator authenticatorGetter
	clientB          databroker.ClientGetter

	ManagerOptions
}

func NewManager(
	clientB databroker.ClientGetter,
	getAuthenticator func(ctx context.Context, idpID string) (identity.Authenticator, error),
	opts ...ManagerOption,
) *DistributedManager {
	options := defaultOptions()
	options.Apply(opts...)
	return &DistributedManager{
		getAuthenticator: getAuthenticator,
		clientB:          clientB,
		ManagerOptions:   *options,
	}
}

var _ Manager = (*DistributedManager)(nil)

type ManagerOptions struct {
	refreshPolicy func() backoff.BackOff
	putPolicy     func() backoff.BackOff

	tracer trace.Tracer
	meter  metric.Meter
}

func (o *ManagerOptions) Apply(opts ...ManagerOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type ManagerOption func(o *ManagerOptions)

func WithRefreshPolicy(b func() backoff.BackOff) ManagerOption {
	return func(o *ManagerOptions) {
		o.refreshPolicy = b
	}
}

func WithPutPolicy(b func() backoff.BackOff) ManagerOption {
	return func(o *ManagerOptions) {
		o.putPolicy = b
	}
}

func WithTracer(tr trace.Tracer) ManagerOption {
	return func(o *ManagerOptions) {
		o.tracer = tr
	}
}

func WithMeter(m metric.Meter) ManagerOption {
	return func(o *ManagerOptions) {
		o.meter = m
	}
}

func defaultOptions() *ManagerOptions {
	return &ManagerOptions{
		refreshPolicy: func() backoff.BackOff {
			return backoff.WithMaxRetries(
				backoff.NewExponentialBackOff(
					backoff.WithInitialInterval(time.Second), backoff.WithMaxElapsedTime(time.Second*5),
				),
				5,
			)
		},
		putPolicy: func() backoff.BackOff {
			return backoff.WithMaxRetries(
				backoff.NewExponentialBackOff(
					backoff.WithInitialInterval(time.Millisecond*50), backoff.WithMaxElapsedTime(time.Second),
				),
				20,
			)
		},
		tracer: otel.Tracer(""),
	}
}

func (s *DistributedManager) Create(
	ctx context.Context,
	id ID,
	token *oauth2.Token,
	rawIDToken string,
) error {
	if err := id.Validate(); err != nil {
		return err
	}
	ctx, span := s.tracer.Start(ctx, "idpsession.Create")
	defer span.End()
	recordID := id.RecordID()
	got, getErr := s.clientB.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(&oauth21.IDPSession{}),
		Id:   recordID,
	})
	if getErr == nil {
		idpSess := &oauth21.IDPSession{}
		if err := got.GetRecord().GetData().UnmarshalTo(idpSess); err != nil {
			return status.Error(codes.FailedPrecondition, fmt.Sprintf("incompatible idpsession : %s", err))
		}
		if idpSess.GetState().GetState() != oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
			// fine to recreate
			panic("what should be the behaviour of calling create here with a session with the same user ID?")
		}
		span.AddEvent("recreate")
		return s.bestEffortCreate(ctx, recordID, rawIDToken, token)
	}
	if status.Code(getErr) != codes.NotFound {
		return getErr
	}
	span.AddEvent("create")

	return s.bestEffortCreate(ctx, recordID, rawIDToken, token)
}

// intentionally create outside the-singleflight path because we don't own the call
// getting the token from the IDP
func (s *DistributedManager) bestEffortCreate(ctx context.Context, recordID string, rawIDToken string, token *oauth2.Token) error {
	b := backoff.WithContext(s.refreshPolicy(), ctx)
	return backoff.Retry(func() error {
		return s.create(ctx, recordID, rawIDToken, token)
	}, b)
}

func (s *DistributedManager) create(
	ctx context.Context,
	recordID string,
	rawIDToken string,
	token *oauth2.Token,
) error {
	idpSess := &oauth21.IDPSession{
		Id:         recordID,
		RawIdToken: rawIDToken,

		State: &oauth21.SessionState{
			State:   oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID,
			Details: "initated",
		},
	}
	UpdateOAuthToken(token, idpSess)
	_, err := s.clientB.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(idpSess),
		},
	})
	return err
}

func (s *DistributedManager) Refresh(ctx context.Context, id ID, state identity.State) (*oauth2.Token, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	ctx, span := s.tracer.Start(ctx, "refresh")
	defer span.End()
	recordID := id.RecordID()

	b := backoff.WithContext(s.refreshPolicy(), ctx)
	i := 0
	token, err := backoff.RetryWithData(func() (token *oauth2.Token, err error) {
		span.AddEvent("tryRefreshSeq", trace.WithAttributes(attribute.Int("seq", i)))
		i++
		authenticator, err := s.getAuthenticator(ctx, id.IdpID)
		if err != nil {
			return nil, err
		}
		client := s.clientB.GetDataBrokerServiceClient()
		changed, _, txErr := databrokerutil.Do(ctx, client, s.updateKey(id), func(tx databrokerutil.TX) error {
			span.AddEvent("tx-fetch")
			idpSess, err := s.fetchAndValidate(ctx, tx, recordID)
			if err != nil {
				return err
			}
			span.AddEvent("tx-refresh")
			if err := s.refreshInFlight(ctx, tx, authenticator, idpSess); err != nil {
				return err
			}
			idpSess.GetRefreshToken().Epoch++

			span.AddEvent("tx-put")
			if err := s.bestEffortPut(ctx, tx, idpSess); err != nil {
				// always fail the outer loop after a successful refresh, but not capable of persisting it.
				return status.Error(codes.FailedPrecondition, fmt.Sprintf("failed to persist refresh : %s", err))
			}
			return nil
		})

		if err := s.handleSingleFlightError(txErr); err != nil {
			return nil, err
		}
		idpSess, retErr := s.handleChangedRecordsFromRefresh(id, changed)
		if retErr != nil {
			return nil, retErr
		}
		state.SetRawIDToken(idpSess.RawIdToken)
		// json marshal+unmarshal round-trip preserves existing identity.State behaviour
		data, err := json.Marshal(idpSess.Claims)
		if err != nil {
			return nil, backoff.Permanent(err)
		}
		if err := json.Unmarshal(data, state); err != nil {
			return nil, backoff.Permanent(err)
		}
		return FromOAuthToken(idpSess), nil
	}, b)
	if err != nil {
		span.SetStatus(otelcode.Error, err.Error())
		return nil, err
	}
	return token, nil
}

func (s *DistributedManager) Revoke(ctx context.Context, id ID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	// intentionally revoke in the non-singleflight path
	// so high contention cannot keep an idpsession indefinitely alive.

	authenticator, err := s.getAuthenticator(ctx, id.IdpID)
	if err != nil {
		return err
	}
	recordID := id.RecordID()
	rec, err := s.clientB.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(&oauth21.IDPSession{}),
		Id:   recordID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	idpSess := &oauth21.IDPSession{}
	if err := rec.GetRecord().GetData().UnmarshalTo(idpSess); err != nil {
		return status.Error(codes.FailedPrecondition, fmt.Sprintf("incompatible idpsession : %s", err))
	}

	if err := authenticator.Revoke(ctx, FromOAuthToken(idpSess)); err != nil {
		return err
	}

	b := backoff.WithContext(s.refreshPolicy(), ctx)
	return backoff.Retry(func() error {
		client := s.clientB.GetDataBrokerServiceClient()
		changed, _, txErr := databrokerutil.Do(ctx, client, s.updateKey(id), func(tx databrokerutil.TX) error {
			resp, err := tx.Get(ctx, &databroker.GetRequest{
				Type: protoutil.GetTypeURL(&oauth21.IDPSession{}),
				Id:   recordID,
			})
			if err != nil {
				return err
			}
			idpSess := &oauth21.IDPSession{}
			if err := resp.GetRecord().GetData().UnmarshalTo(idpSess); err != nil {
				return status.Error(codes.FailedPrecondition, fmt.Sprintf("incompatible idpsession : %s", err))
			}
			if idpSess.GetState().GetState() == oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
				// preserve original state
				return status.Error(codes.FailedPrecondition, "idpsession already revoked")
			}

			s.invalidate(idpSess, "revoked")

			// we don't need to retry here since in theory Revoking with the authenticator will cause refresh operations
			// to fail.
			_, putErr := tx.Put(ctx, &databroker.PutRequest{
				Records: []*databroker.Record{
					databroker.NewRecord(idpSess),
				},
			})
			return putErr
		})

		switch status.Code(txErr) {
		case codes.NotFound:
			return nil
		case codes.FailedPrecondition:
			if strings.Contains(txErr.Error(), "idpsession already revoked") {
				return nil
			}
			return backoff.Permanent(txErr)
		default:
			if txErr != nil {
				return txErr
			}
		}
		if len(changed) == 0 {
			panic("bug: changed records should always have len>0 when singleflight err!=nil")
		}
		for _, rec := range fastForwardRecords(changed) {
			if rec.GetId() == recordID {
				retIdpSess := &oauth21.IDPSession{}
				if err := rec.GetData().UnmarshalTo(retIdpSess); err != nil {
					return backoff.Permanent(
						fmt.Errorf("incompatible transaction result from refresh : %w", err),
					)
				}
				if retIdpSess.GetState().GetState() == oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
					return nil
				}
				return fmt.Errorf("not yet revoked, retry")
			}
		}
		panic("bug : matching idpsession with id not found in changed results")
	}, b)
}

func (s *DistributedManager) invalidate(idpSess *oauth21.IDPSession, details string) {
	idpSess.State = &oauth21.SessionState{
		State:   oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
		Details: details,
	}
}

func (s *DistributedManager) refreshInFlight(
	ctx context.Context,
	tx databrokerutil.TX,
	authenticator identity.Authenticator,
	idpSess *oauth21.IDPSession,
) error {
	newToken, refreshErr := authenticator.Refresh(ctx, FromOAuthToken(idpSess), idpSess)
	if refreshErr != nil {
		if isTemporaryError(refreshErr) {
			return refreshErr
		}
		s.invalidate(idpSess, refreshErr.Error())
		if _, putErr := tx.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{
				databroker.NewRecord(idpSess),
			},
		}); putErr != nil {
			return putErr
		}
		return nil
	}

	UpdateOAuthToken(newToken, idpSess)
	return nil
}

func (s *DistributedManager) fetchAndValidate(ctx context.Context, tx databrokerutil.TX, recordID string) (*oauth21.IDPSession, error) {
	got, err := tx.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(&oauth21.IDPSession{}),
		Id:   recordID,
	})
	if err != nil {
		return nil, err
	}

	rec := got.GetRecord()
	idpSess := &oauth21.IDPSession{}
	if err := rec.GetData().UnmarshalTo(idpSess); err != nil {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("incompatible idpsession record : %s", err))
	}

	if err := validateIDPSession(idpSess); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "invalid")
	}
	return idpSess, nil
}

// bestEffortPut explicitly retries aggresively after a refresh, since they refresh tokens can be consume on-use and
// can't ber retried if a refresh succeeded but we proceeded to the outer loop.
func (s *DistributedManager) bestEffortPut(ctx context.Context, tx databrokerutil.TX, idpSess *oauth21.IDPSession) error {
	b := backoff.WithContext(s.putPolicy(), ctx)
	backoffErr := backoff.Retry(func() error {
		_, putErr := tx.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{
				databroker.NewRecord(idpSess),
			},
		})
		return putErr
	}, b)
	return backoffErr
}

func (s *DistributedManager) handleSingleFlightError(txErr error) error {
	if txErr != nil {
		if code := status.Code(txErr); code == codes.NotFound || code == codes.FailedPrecondition {
			return backoff.Permanent(fmt.Errorf("idp session no longer valid : %w", txErr))
		}
		return txErr
	}
	return nil
}

func (s *DistributedManager) handleChangedRecordsFromRefresh(
	id ID,
	changed []*databroker.Record,
) (*oauth21.IDPSession, error) {
	for _, rec := range fastForwardRecords(changed) {
		if rec.GetId() == id.RecordID() {
			retIdpSess := &oauth21.IDPSession{}
			if err := rec.GetData().UnmarshalTo(retIdpSess); err != nil {
				return nil, backoff.Permanent(
					fmt.Errorf("incompatible transaction result from refresh : %w", err),
				)
			}

			switch retIdpSess.GetState().State {
			case oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_UKNOWN:
			case oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID:
				if details := retIdpSess.GetState().GetDetails(); details != "" {
					return nil, backoff.Permanent(
						fmt.Errorf("idpsession is no longer usable : %s", details),
					)
				}
				return nil, backoff.Permanent(
					fmt.Errorf("idpsession is no longer usable"),
				)
			}

			return retIdpSess, nil
		}
	}
	panic("bug: changed records should always have len>0 when singleflight err!=nil")
}

func (s *DistributedManager) updateKey(id ID) string {
	return path.Join(id.RecordID(), "update")
}

func validateIDPSession(idpSess *oauth21.IDPSession) error {
	switch idpSess.GetState().GetState() {
	case oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID:
		if details := idpSess.GetState().GetDetails(); details != "" {
			return fmt.Errorf("upstream session no longer valid : %s", details)
		}
		return fmt.Errorf("upstream session no longer valid")
	case oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID:
		return nil
	default:
		if details := idpSess.GetState().GetDetails(); details != "" {
			return fmt.Errorf("unknown upstream session state : %s", details)
		}
		return fmt.Errorf("unknown upstream session state")
	}
}

func fastForwardRecords(recs []*databroker.Record) []*databroker.Record {
	slices.Reverse(recs)
	return sliceutil.UniqueBy(recs, func(rec *databroker.Record) [2]string {
		return [2]string{rec.GetType(), rec.GetId()}
	})
}
