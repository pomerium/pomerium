package authenticateflow

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

type BindingID struct {
	// Follow up :when SSH implements the new binding abstraction, replace this
	// with the enum.
	Protocol  string
	UserID    string
	BindingID string
}

type BindingManager interface {
	// DeleteUpstreamIDPSessions deletes all associated idpSessions with the same upstream IDP session.
	// If we can't determine which upstream IDPSession it is associated with, we delete all IDPSessions for this user.
	DeleteUpstreamIDPSessions(ctx context.Context, h *session.Handle) (IDPSessionRevocation, error)
	RevokeBinding(ctx context.Context, id BindingID) error
	GetIDPSessions(ctx context.Context, h *session.Handle) ([]handlers.IDPSessionData, string, error)
	GetBindings(ctx context.Context, h *session.Handle) ([]handlers.SessionBindingData, error)
}

type IDPSessionRevocation struct {
	Source   *idpsession.IDPSession
	Sessions []*idpsession.IDPSession
}

func NewBindingManager(client databroker.DataBrokerServiceClient) BindingManager {
	return &bindingManager{
		dataBrokerClient: client,
		codeRevoker:      code.NewRevoker(databroker.NewStaticClientGetter(client)),
		codeReader:       code.NewReader(databroker.NewStaticClientGetter(client)),
	}
}

type bindingManager struct {
	dataBrokerClient databroker.DataBrokerServiceClient
	codeRevoker      code.Revoker
	codeReader       code.Reader
}

var errRevoke = httputil.NewError(http.StatusInternalServerError, fmt.Errorf("failed to revoke session binding"))

func (b *bindingManager) DeleteUpstreamIDPSessions(
	ctx context.Context,
	h *session.Handle,
) (IDPSessionRevocation, error) {
	if h == nil {
		return IDPSessionRevocation{}, httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
	}
	binding, err := idpsession.GetBinding(ctx, b.dataBrokerClient, h.GetId())
	if err != nil || binding.GetUserId() != h.GetUserId() ||
		binding.GetProtocol() != idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER ||
		binding.GetTypeUrl() != "type.googleapis.com/session.Session" {
		if status.Code(err) == codes.NotFound || err == nil {
			return IDPSessionRevocation{}, httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
		}
		return IDPSessionRevocation{}, errRevoke
	}

	parent, err := b.getIDPSession(ctx, binding.GetIdpSessionId())
	if err != nil || parent.GetUserId() != h.GetUserId() {
		if status.Code(err) == codes.NotFound || err == nil {
			return IDPSessionRevocation{}, httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
		}
		return IDPSessionRevocation{}, errRevoke
	}

	filter := map[string]any{"user_id": parent.GetUserId()}
	if parent.GetSid() != "" {
		filter = map[string]any{"sid": parent.GetSid()}
	}
	records, sessions, err := b.queryIDPSessions(ctx, filter)
	if err != nil {
		return IDPSessionRevocation{}, errRevoke
	}
	if len(records) == 0 {
		return IDPSessionRevocation{}, httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
	}

	deletedAt := timestamppb.Now()
	for _, record := range records {
		record.DeletedAt = deletedAt
	}
	if _, err := b.dataBrokerClient.Put(ctx, &databroker.PutRequest{Records: records}); err != nil {
		return IDPSessionRevocation{}, errRevoke
	}
	return IDPSessionRevocation{Source: parent, Sessions: sessions}, nil
}

func (b *bindingManager) getIDPSession(ctx context.Context, id string) (*idpsession.IDPSession, error) {
	response, err := b.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(idpsession.IDPSession)),
		Id:   id,
	})
	if err != nil {
		return nil, err
	}
	idpSess := new(idpsession.IDPSession)
	if err := response.GetRecord().GetData().UnmarshalTo(idpSess); err != nil {
		return nil, err
	}
	return idpSess, nil
}

func (b *bindingManager) queryIDPSessions(
	ctx context.Context,
	fields map[string]any,
) ([]*databroker.Record, []*idpsession.IDPSession, error) {
	filter, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, nil, err
	}
	const limit = int64(100)
	var records []*databroker.Record
	var sessions []*idpsession.IDPSession
	for offset := int64(0); ; offset += limit {
		response, err := b.dataBrokerClient.Query(ctx, &databroker.QueryRequest{
			Type: protoutil.GetTypeURL(new(idpsession.IDPSession)), Offset: offset, Limit: limit, Filter: filter,
		})
		if err != nil {
			return nil, nil, err
		}
		for _, record := range response.GetRecords() {
			if record.GetDeletedAt() != nil {
				continue
			}
			session := new(idpsession.IDPSession)
			if err := record.GetData().UnmarshalTo(session); err != nil {
				return nil, nil, err
			}
			records = append(records, record)
			sessions = append(sessions, session)
		}
		if len(response.GetRecords()) < int(limit) || offset+limit >= response.GetTotalCount() {
			break
		}
	}
	return records, sessions, nil
}

func (b *bindingManager) GetIDPSessions(ctx context.Context, h *session.Handle) ([]handlers.IDPSessionData, string, error) {
	currentIDPSessionID := ""
	if binding, err := idpsession.GetBinding(ctx, b.dataBrokerClient, h.GetId()); err == nil &&
		binding.GetUserId() == h.GetUserId() {
		currentIDPSessionID = binding.GetIdpSessionId()
	}
	filter, err := structpb.NewStruct(map[string]any{
		"user_id": h.UserId,
	})
	if err != nil {
		return nil, "", httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}
	resp, err := b.dataBrokerClient.Query(ctx, &databroker.QueryRequest{
		Type:   protoutil.GetTypeURL(new(idpsession.IDPSession)),
		Filter: filter,
		Limit:  100,
	})
	if err != nil {
		return nil, "", httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}
	ret := make([]handlers.IDPSessionData, 0, len(resp.GetRecords()))
	for _, rec := range resp.GetRecords() {
		idpSess := &idpsession.IDPSession{}
		if err := rec.GetData().UnmarshalTo(idpSess); err != nil {
			log.Ctx(ctx).Err(err).Str("session-id", h.Id).Str("record-id", rec.GetId()).Msg("processing IDPSession")
			continue
		}

		datum := handlers.IDPSessionData{
			IDPSessionID:  rec.GetId(),
			SID:           idpSess.GetSid(),
			InitiatedAt:   idpSess.GetInitiatedAt().AsTime().Format(time.RFC1123),
			ClientAddress: "unknown client address",
			Resource:      "Uknown client",
		}
		if idpSess.InitatedBy != nil {
			datum.Resource = *idpSess.InitatedBy
		}
		if idpSess.InitiatedByAddr != nil {
			datum.ClientAddress = *idpSess.InitiatedByAddr
		}

		ret = append(ret, datum)
	}
	slices.SortFunc(ret, func(a, b handlers.IDPSessionData) int {
		return cmp.Compare(a.IDPSessionID, b.IDPSessionID)
	})
	return ret, currentIDPSessionID, nil
}

func (b *bindingManager) RevokeBinding(ctx context.Context, bindingID BindingID) error {
	id := bindingID.BindingID
	protocol := bindingID.Protocol
	userID := bindingID.UserID
	log.Ctx(ctx).Debug().Str("binding-id", id).Str("protocol", protocol).Msg("revoking binding")

	if bindingID.Protocol == session.ProtocolSSH {
		if err := b.codeRevoker.RevokeSessionBinding(ctx, code.BindingID(id)); err != nil {
			return errRevoke
		}
		return nil
	}
	if protocol == "Browser" {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("bad request"))
	}
	binding := &idpsession.Binding{}
	rec, err := b.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(binding),
		Id:   id,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
		}
		return errRevoke
	}

	if err := rec.GetRecord().GetData().UnmarshalTo(binding); err != nil {
		return errRevoke
	}

	if binding.GetUserId() != userID {
		return httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
	}

	if binding.GetProtocol() == idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("browser bindings are not revocable"))
	}

	toDelete := databroker.NewRecord(binding)
	toDelete.DeletedAt = timestamppb.Now()

	if _, err := b.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			toDelete,
		},
	}); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}
	return nil
}

func (b *bindingManager) GetBindings(ctx context.Context, h *session.Handle) ([]handlers.SessionBindingData, error) {
	sshBindings, err := b.getLegacySSHSessionBindingInfo(ctx, h.UserId)
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}
	otherBindings, err := b.getIDPSessionBindings(ctx, h)
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}
	allBindings := map[string][]handlers.SessionBindingData{}
	maps.Copy(allBindings, sshBindings)
	for k, incoming := range otherBindings {
		existing, ok := allBindings[k]
		if ok {
			allBindings[k] = append(existing, incoming...)
		} else {
			allBindings[k] = incoming
		}
	}

	ret := make([]handlers.SessionBindingData, 0)
	for idpSessionID, bindings := range allBindings {
		for _, binding := range bindings {
			binding.IDPSessionID = idpSessionID
			ret = append(ret, binding)
		}
	}
	slices.SortFunc(ret, func(a, b handlers.SessionBindingData) int {
		if n := cmp.Compare(a.IDPSessionID, b.IDPSessionID); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Protocol, b.Protocol); n != 0 {
			return n
		}
		return cmp.Compare(a.SessionBindingID, b.SessionBindingID)
	})

	return ret, nil
}

func (b *bindingManager) getLegacySSHSessionBindingInfo(ctx context.Context, userID string) (map[string][]handlers.SessionBindingData, error) {
	pairs, err := b.codeReader.GetSessionBindingsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch ssh bindings")
	}

	renderData := map[string][]handlers.SessionBindingData{}
	idpSessionIDs := map[string]string{}
	stableKeys := slices.Collect(maps.Keys(pairs))
	slices.Sort(stableKeys)

	for _, sessionBindingID := range stableKeys {
		p := pairs[sessionBindingID]

		datum := handlers.SessionBindingData{
			SessionBindingID:   sessionBindingID,
			Protocol:           p.SB.Protocol,
			Resource:           "SSH key",
			InitiatedAt:        p.SB.IssuedAt.AsTime().Format(time.RFC1123),
			ExpiresAt:          p.SB.ExpiresAt.AsTime().Format(time.RFC1123),
			HasIdentityBinding: p.IB != nil,
		}
		if p.SB.Protocol == session.ProtocolSSH {
			sshDetails := &handlers.ProtocolDetailsSSH{
				FingerprintID: strings.TrimPrefix(sessionBindingID, "sshkey-SHA256:"),
			}
			if p.SB.Details != nil && p.SB.Details[session.DetailSourceAddr] != "" {
				sshDetails.SourceAddress = p.SB.Details[session.DetailSourceAddr]
			} else {
				sshDetails.SourceAddress = "Not recorded"
			}
			datum.DetailsSSH = sshDetails
			datum.ClientAddress = sshDetails.SourceAddress
		}

		if p.IB != nil {
			datum.ExpiresAt = "Until revoked"
		} else {
			datum.ExpiresAt = p.SB.ExpiresAt.AsTime().Format(time.RFC1123)
		}
		idpSessionID, ok := idpSessionIDs[p.SB.GetSessionId()]
		if !ok {
			binding, err := idpsession.GetBinding(ctx, b.dataBrokerClient, p.SB.GetSessionId())
			if err != nil || binding.GetUserId() != userID {
				log.Ctx(ctx).Debug().Err(err).
					Str("session-id", p.SB.GetSessionId()).
					Msg("could not associate SSH binding with IDP session")
				continue
			}
			idpSessionID = binding.GetIdpSessionId()
			idpSessionIDs[p.SB.GetSessionId()] = idpSessionID
		}
		bindings, ok := renderData[idpSessionID]
		if !ok {
			bindings = []handlers.SessionBindingData{}
			renderData[idpSessionID] = bindings
		}
		renderData[idpSessionID] = append(bindings, datum)
	}
	return renderData, nil
}

func (b *bindingManager) getIDPSessionBindings(
	ctx context.Context,
	h *session.Handle,
) (map[string][]handlers.SessionBindingData, error) {
	filter, err := structpb.NewStruct(map[string]any{
		"user_id": h.UserId,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build IDP session binding filter: %w", err)
	}
	response, err := b.dataBrokerClient.Query(ctx, &databroker.QueryRequest{
		Type:   protoutil.GetTypeURL(&idpsession.Binding{}),
		Filter: filter,
		Limit:  100,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("could not fetch IDP session bindings: %w", err)
	}

	renderData := map[string][]handlers.SessionBindingData{}
	for _, record := range response.GetRecords() {
		if record.GetDeletedAt() != nil {
			continue
		}

		binding := new(idpsession.Binding)
		if err := record.GetData().UnmarshalTo(binding); err != nil {
			return nil, fmt.Errorf("could not decode IDP session binding %q: %w", record.GetId(), err)
		}
		bindingType := binding.GetTypeUrl()

		// not user visible session
		if bindingType != "type.googleapis.com/session.Session" {
			continue
		}
		// ignore browser sessions since they can't be revoked like other bindings -
		// they require a sign-out flow.
		if binding.Protocol == idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER {
			continue
		}

		datum, err := b.sessionToBindingData(ctx, binding)
		if err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to fetch session binding information")
			continue
		}
		bindings, ok := renderData[binding.IdpSessionId]
		if !ok {
			bindings = []handlers.SessionBindingData{}
			renderData[binding.IdpSessionId] = bindings
		}
		renderData[binding.IdpSessionId] = append(bindings, datum)
	}
	return renderData, nil
}

func (b *bindingManager) sessionToBindingData(
	ctx context.Context,
	binding *idpsession.Binding,
) (handlers.SessionBindingData, error) {
	var expiresAt string
	var clientAddr string
	var resource string

	switch binding.GetTypeUrl() {
	case protoutil.GetTypeURL(&session.Session{}):
		rec, err := b.dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: protoutil.GetTypeURL(&session.Session{}),
			Id:   binding.GetId(),
		})
		if err != nil {
			return handlers.SessionBindingData{}, err
		}
		switch binding.GetProtocol() {
		case idpsession.BindingProtocol_BINDING_PROTOCOL_MCP:
			expiresAt = "Until revoked or IDP expires"
			resource = binding.GetDetails()["mcp_client_id"]
		case idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER:
			sess := &session.Session{}
			if err := rec.GetRecord().GetData().UnmarshalTo(sess); err != nil {
				return handlers.SessionBindingData{}, err
			}
			expiresAt = sess.GetExpiresAt().AsTime().Format(time.RFC1123)
			resource = formatBrowserUserAgent(binding.GetDetails()["user-agent"])
		}
		clientAddr = binding.GetDetails()["client-ip"]
	}

	datum := handlers.SessionBindingData{
		SessionBindingID: binding.GetId(),
		Protocol:         formatProtocol(binding.GetProtocol()),
		ClientAddress:    clientAddr,
		ExpiresAt:        expiresAt,
		Resource:         resource,
	}

	if binding.GetInitiatedAt() != nil {
		datum.InitiatedAt = binding.GetInitiatedAt().AsTime().Format(time.RFC1123)
	}
	return datum, nil
}

func formatProtocol(protocol idpsession.BindingProtocol) string {
	switch protocol {
	case idpsession.BindingProtocol_BINDING_PROTOCOL_MCP:
		return "MCP"
	case idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER:
		return "Browser"
	}
	return "Unknown"
}
