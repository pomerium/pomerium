package oidcbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// The databroker bounds how many of these records it keeps (see
// setupRequiredIndex).
var redeemedCodeType = protoutil.GetTypeURL(new(oauth21proto.RedeemedAuthorizationCode))

// codeID identifies an authorization code. Each code is distinct (its
// encryption uses a random nonce), so its hash identifies it.
func codeID(code string) string {
	id := sha256.Sum256([]byte(code))
	return hex.EncodeToString(id[:])
}

// redeemCode records that the request's authorization code was exchanged. If
// it already was, it revokes the tokens issued for it and fails with
// invalid_grant. Without a databroker client codes are not single-use.
func (h *Handlers) redeemCode(ctx context.Context, req *ValidatedTokenRequest) error {
	if h.dataBrokerClient == nil {
		return nil
	}

	redeemed := &oauth21proto.RedeemedAuthorizationCode{
		ClientId:  req.ClientID,
		ExpiresAt: timestamppb.New(req.CodeExpiration),
	}
	record := &databroker.Record{
		Type: redeemedCodeType,
		Id:   req.CodeID,
		Data: protoutil.NewAny(redeemed),
	}
	// Version 0 means "create only if absent", so concurrent redemptions
	// cannot both succeed.
	_, err := databroker.PutIfMatchVersion(ctx, h.dataBrokerClient, record)
	if databroker.IsRecordVersionMismatch(err) {
		redeemed.Revoked = true
		record.Data = protoutil.NewAny(redeemed)
		_, err := h.dataBrokerClient.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{record}})
		if err != nil {
			return fmt.Errorf("revoke tokens for replayed code: %w", err)
		}
		return &errorResponse{
			ErrorCode:   "invalid_grant",
			Description: "authorization code was already used",
		}
	} else if err != nil {
		return fmt.Errorf("record redeemed code: %w", err)
	}
	return nil
}

// codeRevoked returns whether the tokens issued for the authorization code
// with the given ID were revoked because the code was replayed.
func (h *Handlers) codeRevoked(ctx context.Context, id string) (bool, error) {
	if h.dataBrokerClient == nil || id == "" {
		return false, nil
	}
	res, err := h.dataBrokerClient.Get(ctx, &databroker.GetRequest{Type: redeemedCodeType, Id: id})
	if databroker.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("get redeemed code: %w", err)
	}
	var redeemed oauth21proto.RedeemedAuthorizationCode
	if err := res.GetRecord().GetData().UnmarshalTo(&redeemed); err != nil {
		return false, fmt.Errorf("unmarshal redeemed code: %w", err)
	}
	return redeemed.GetRevoked(), nil
}
