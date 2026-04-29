package storagetest

import (
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
)

func TestConfigServiceAvailableLogFields(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	listRes, err := client.ListAvailableLogFields(t.Context(), connect.NewRequest(&configpb.ListAvailableLogFieldsRequest{}))
	assert.NoError(t, err)
	assert.NotEmpty(t, listRes.Msg.AvailableAccessLogFields)
	assert.NotEmpty(t, listRes.Msg.AvailableAuthorizeLogFields)
	assert.NotEmpty(t, listRes.Msg.DefaultAccessLogFields)
	assert.NotEmpty(t, listRes.Msg.DefaultAuthorizeLogFields)
}

func TestConfigServiceKeyPairs(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	listRes, err := client.ListKeyPairs(t.Context(), connect.NewRequest(&configpb.ListKeyPairsRequest{}))
	assert.NoError(t, err)
	assert.Empty(t, listRes.Msg.KeyPairs, "should return no key pairs when none of have been added yet")

	for i := range 1000 {
		res, err := client.CreateKeyPair(t.Context(), connect.NewRequest(&configpb.CreateKeyPairRequest{
			KeyPair: &configpb.KeyPair{
				Id:   new(fmt.Sprintf("kp-%04d", i+1)),
				Name: new(fmt.Sprintf("key-pair-%04d", i+1)),
			},
		}))
		assert.NoError(t, err)
		assert.NotNil(t, res.Msg.KeyPair)
	}

	_, err = client.CreateKeyPair(t.Context(), connect.NewRequest(&configpb.CreateKeyPairRequest{
		KeyPair: &configpb.KeyPair{
			Id: new("kp-0300"),
		},
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "should prevent creation of key pairs with the same id")

	listRes, err = client.ListKeyPairs(t.Context(), connect.NewRequest(&configpb.ListKeyPairsRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.KeyPairs, 10)
		assert.Equal(t, uint64(1000), listRes.Msg.TotalCount)
		assert.Equal(t, "kp-1000", listRes.Msg.KeyPairs[0].GetId(), "should be sorted by id, descending")
	}

	getRes, err := client.GetKeyPair(t.Context(), connect.NewRequest(&configpb.GetKeyPairRequest{
		Id: "kp-1000",
	}))
	if assert.NoError(t, err) {
		assert.Empty(t, cmp.Diff(listRes.Msg.KeyPairs[0], getRes.Msg.KeyPair, protocmp.Transform()))
	}

	listRes, err = client.ListKeyPairs(t.Context(), connect.NewRequest(&configpb.ListKeyPairsRequest{
		Limit: new(uint64(10)),
		Filter: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue("kp-1000"),
			},
		},
	}))
	if assert.NoError(t, err) && assert.Len(t, listRes.Msg.KeyPairs, 1) {
		assert.Equal(t, "kp-1000", listRes.Msg.KeyPairs[0].GetId(), "should filter by id")
	}

	_, err = client.DeleteKeyPair(t.Context(), connect.NewRequest(&configpb.DeleteKeyPairRequest{Id: "UNKNOWN"}))
	assert.NoError(t, err, "should allow deletion of key pairs which don't exist")
	_, err = client.DeleteKeyPair(t.Context(), connect.NewRequest(&configpb.DeleteKeyPairRequest{Id: "kp-1000"}))
	assert.NoError(t, err)

	listRes, err = client.ListKeyPairs(t.Context(), connect.NewRequest(&configpb.ListKeyPairsRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.KeyPairs, 10)
		assert.Equal(t, uint64(999), listRes.Msg.TotalCount)
		assert.Equal(t, "kp-0999", listRes.Msg.KeyPairs[0].GetId(), "should delete the last key pair")
	}

	kp := proto.CloneOf(listRes.Msg.KeyPairs[0])
	kp.Name = new("key-pair-0999-updated")
	_, err = client.UpdateKeyPair(t.Context(), connect.NewRequest(&configpb.UpdateKeyPairRequest{
		KeyPair: kp,
	}))
	assert.NoError(t, err)

	getRes, err = client.GetKeyPair(t.Context(), connect.NewRequest(&configpb.GetKeyPairRequest{
		Id: "kp-0999",
	}))
	if assert.NoError(t, err) {
		assert.Equal(t, "key-pair-0999-updated", getRes.Msg.GetKeyPair().GetName())
		assert.NotEmpty(t, cmp.Diff(kp.GetModifiedAt(), getRes.Msg.GetKeyPair().GetModifiedAt(), protocmp.Transform()),
			"should update the modified at timestamp")
	}

	_, err = client.ListKeyPairs(t.Context(), connect.NewRequest(&configpb.ListKeyPairsRequest{
		OrderBy: new("gobbledygook"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "should reject list requests with bad order by arguments")

	_, err = client.GetKeyPair(t.Context(), connect.NewRequest(&configpb.GetKeyPairRequest{Id: "UNKNOWN"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "should return not found for a key pair that doesn't exist")
}

func TestConfigServicePolicies(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	_, err := client.CreatePolicy(t.Context(), connect.NewRequest(&configpb.CreatePolicyRequest{
		Policy: &configpb.Policy{
			Id:        new("invalid-policy"),
			SourcePpl: new("<INVALID>"),
		},
	}))
	require.Equal(t, connect.CodeInvalidArgument.String(), connect.CodeOf(err).String(), "should validate policies")

	listRes, err := client.ListPolicies(t.Context(), connect.NewRequest(&configpb.ListPoliciesRequest{}))
	assert.NoError(t, err)
	assert.Empty(t, listRes.Msg.Policies, "should return no policies when none of have been added yet")

	for i := range 1000 {
		res, err := client.CreatePolicy(t.Context(), connect.NewRequest(&configpb.CreatePolicyRequest{
			Policy: &configpb.Policy{
				Id:   new(fmt.Sprintf("p-%04d", i+1)),
				Name: new(fmt.Sprintf("policy-%04d", i+1)),
			},
		}))
		assert.NoError(t, err)
		assert.NotNil(t, res.Msg.Policy)
	}

	_, err = client.CreatePolicy(t.Context(), connect.NewRequest(&configpb.CreatePolicyRequest{
		Policy: &configpb.Policy{
			Id: new("p-0300"),
		},
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "should prevent creation of policies with the same id")

	listRes, err = client.ListPolicies(t.Context(), connect.NewRequest(&configpb.ListPoliciesRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.Policies, 10)
		assert.Equal(t, uint64(1000), listRes.Msg.TotalCount)
		assert.Equal(t, "p-1000", listRes.Msg.Policies[0].GetId(), "should be sorted by id, descending")
	}

	getRes, err := client.GetPolicy(t.Context(), connect.NewRequest(&configpb.GetPolicyRequest{
		Id: "p-1000",
	}))
	if assert.NoError(t, err) {
		assert.Empty(t, cmp.Diff(listRes.Msg.Policies[0], getRes.Msg.Policy, protocmp.Transform()))
	}

	listRes, err = client.ListPolicies(t.Context(), connect.NewRequest(&configpb.ListPoliciesRequest{
		Limit: new(uint64(10)),
		Filter: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue("p-1000"),
			},
		},
	}))
	if assert.NoError(t, err) && assert.Len(t, listRes.Msg.Policies, 1) {
		assert.Equal(t, "p-1000", listRes.Msg.Policies[0].GetId(), "should filter by id")
	}

	_, err = client.DeletePolicy(t.Context(), connect.NewRequest(&configpb.DeletePolicyRequest{Id: "UNKNOWN"}))
	assert.NoError(t, err, "should allow deletion of policies which don't exist")
	_, err = client.DeletePolicy(t.Context(), connect.NewRequest(&configpb.DeletePolicyRequest{Id: "p-1000"}))
	assert.NoError(t, err)

	listRes, err = client.ListPolicies(t.Context(), connect.NewRequest(&configpb.ListPoliciesRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.Policies, 10)
		assert.Equal(t, uint64(999), listRes.Msg.TotalCount)
		assert.Equal(t, "p-0999", listRes.Msg.Policies[0].GetId(), "should delete the last policy")
	}

	p := proto.CloneOf(listRes.Msg.Policies[0])
	p.Name = new("policy-0999-updated")
	_, err = client.UpdatePolicy(t.Context(), connect.NewRequest(&configpb.UpdatePolicyRequest{
		Policy: p,
	}))
	assert.NoError(t, err)

	getRes, err = client.GetPolicy(t.Context(), connect.NewRequest(&configpb.GetPolicyRequest{
		Id: "p-0999",
	}))
	if assert.NoError(t, err) {
		assert.Equal(t, "policy-0999-updated", getRes.Msg.GetPolicy().GetName())
		assert.NotEmpty(t, cmp.Diff(p.GetModifiedAt(), getRes.Msg.GetPolicy().GetModifiedAt(), protocmp.Transform()),
			"should update the modified at timestamp")
	}

	_, err = client.ListPolicies(t.Context(), connect.NewRequest(&configpb.ListPoliciesRequest{
		OrderBy: new("gobbledygook"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "should reject list requests with bad order by arguments")

	_, err = client.GetPolicy(t.Context(), connect.NewRequest(&configpb.GetPolicyRequest{Id: "UNKNOWN"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "should return not found for a policy that doesn't exist")
}

func TestConfigServiceRoutes(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	_, err := client.CreateRoute(t.Context(), connect.NewRequest(&configpb.CreateRouteRequest{
		Route: &configpb.Route{
			Id:   new("invalid-route"),
			From: "<INVALID>",
		},
	}))
	assert.Equal(t, connect.CodeInvalidArgument.String(), connect.CodeOf(err).String(), "should validate routes")

	listRes, err := client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{}))
	assert.NoError(t, err)
	assert.Empty(t, listRes.Msg.Routes, "should return no routes when none have been added yet")

	for i := range 1000 {
		res, err := client.CreateRoute(t.Context(), connect.NewRequest(&configpb.CreateRouteRequest{
			Route: &configpb.Route{
				Id:   new(fmt.Sprintf("r-%04d", i+1)),
				Name: new(fmt.Sprintf("route-%04d", i+1)),
				From: fmt.Sprintf("https://from-%04d.example.com", i+1),
				To:   []string{fmt.Sprintf("https://to-%04d.example.com", i+1)},
			},
		}))
		require.NoError(t, err)
		assert.NotNil(t, res.Msg.Route)
	}

	_, err = client.CreateRoute(t.Context(), connect.NewRequest(&configpb.CreateRouteRequest{
		Route: &configpb.Route{
			Id:   new("r-0300"),
			Name: new("route-0300"),
			From: "https://from-0300.example.com",
			To:   []string{"https://to-0300.example.com"},
		},
	}))
	assert.Equal(t, connect.CodeAlreadyExists.String(), connect.CodeOf(err).String(), "should prevent creation of routes with the same id")

	listRes, err = client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.Routes, 10)
		assert.Equal(t, uint64(1000), listRes.Msg.TotalCount)
		assert.Equal(t, "r-1000", listRes.Msg.Routes[0].GetId(), "should be sorted by id, descending")
	}

	getRes, err := client.GetRoute(t.Context(), connect.NewRequest(&configpb.GetRouteRequest{
		Id: "r-1000",
	}))
	if assert.NoError(t, err) {
		assert.Empty(t, cmp.Diff(listRes.Msg.Routes[0], getRes.Msg.Route, protocmp.Transform()))
	}

	listRes, err = client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{
		Limit: new(uint64(10)),
		Filter: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue("r-1000"),
			},
		},
	}))
	if assert.NoError(t, err) && assert.Len(t, listRes.Msg.Routes, 1) {
		assert.Equal(t, "r-1000", listRes.Msg.Routes[0].GetId(), "should filter by id")
	}

	_, err = client.DeleteRoute(t.Context(), connect.NewRequest(&configpb.DeleteRouteRequest{Id: "UNKNOWN"}))
	assert.NoError(t, err, "should allow deletion of routes which don't exist")
	_, err = client.DeleteRoute(t.Context(), connect.NewRequest(&configpb.DeleteRouteRequest{Id: "r-1000"}))
	assert.NoError(t, err)

	listRes, err = client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.Routes, 10)
		assert.Equal(t, uint64(999), listRes.Msg.TotalCount)
		assert.Equal(t, "r-0999", listRes.Msg.Routes[0].GetId(), "should delete the last route")
	}

	r := proto.CloneOf(listRes.Msg.Routes[0])
	r.Name = new("route-0999-updated")
	_, err = client.UpdateRoute(t.Context(), connect.NewRequest(&configpb.UpdateRouteRequest{
		Route: r,
	}))
	assert.NoError(t, err)

	getRes, err = client.GetRoute(t.Context(), connect.NewRequest(&configpb.GetRouteRequest{
		Id: "r-0999",
	}))
	if assert.NoError(t, err) {
		assert.Equal(t, "route-0999-updated", getRes.Msg.GetRoute().GetName())
		assert.NotEmpty(t, cmp.Diff(r.GetModifiedAt(), getRes.Msg.GetRoute().GetModifiedAt(), protocmp.Transform()),
			"should update the modified at timestamp")
	}

	_, err = client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{
		OrderBy: new("gobbledygook"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "should reject list requests with bad order by arguments")

	_, err = client.GetRoute(t.Context(), connect.NewRequest(&configpb.GetRouteRequest{Id: "UNKNOWN"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "should return not found for a route that doesn't exist")
}

func TestConfigServiceServiceAccounts(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	listRes, err := client.ListServiceAccounts(t.Context(), connect.NewRequest(&configpb.ListServiceAccountsRequest{}))
	assert.NoError(t, err)
	assert.Empty(t, listRes.Msg.ServiceAccounts, "should return no service accounts when none of have been added yet")

	for i := range 1000 {
		res, err := client.CreateServiceAccount(t.Context(), connect.NewRequest(&configpb.CreateServiceAccountRequest{
			ServiceAccount: &configpb.ServiceAccount{
				Id:     new(fmt.Sprintf("s-%04d", i+1)),
				UserId: new(fmt.Sprintf("u-%04d", (i%10)+1)),
			},
		}))
		assert.NoError(t, err)
		assert.NotNil(t, res.Msg.ServiceAccount)
		assert.NotEmpty(t, res.Msg.Jwt)
	}

	_, err = client.CreateServiceAccount(t.Context(), connect.NewRequest(&configpb.CreateServiceAccountRequest{
		ServiceAccount: &configpb.ServiceAccount{
			Id: new("s-0300"),
		},
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "should prevent creation of service accounts with the same id")

	listRes, err = client.ListServiceAccounts(t.Context(), connect.NewRequest(&configpb.ListServiceAccountsRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.ServiceAccounts, 10)
		assert.Equal(t, uint64(1000), listRes.Msg.TotalCount)
		assert.Equal(t, "s-1000", listRes.Msg.ServiceAccounts[0].GetId(), "should be sorted by id, descending")
		assert.Equal(t, "u-0010", listRes.Msg.ServiceAccounts[0].GetUserId())
	}

	getRes, err := client.GetServiceAccount(t.Context(), connect.NewRequest(&configpb.GetServiceAccountRequest{
		Id: "s-1000",
	}))
	if assert.NoError(t, err) {
		assert.Empty(t, cmp.Diff(listRes.Msg.ServiceAccounts[0], getRes.Msg.ServiceAccount, protocmp.Transform()))
	}

	listRes, err = client.ListServiceAccounts(t.Context(), connect.NewRequest(&configpb.ListServiceAccountsRequest{
		Limit: new(uint64(10)),
		Filter: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue("s-1000"),
			},
		},
	}))
	if assert.NoError(t, err) && assert.Len(t, listRes.Msg.ServiceAccounts, 1) {
		assert.Equal(t, "s-1000", listRes.Msg.ServiceAccounts[0].GetId(), "should filter by id")
	}

	_, err = client.DeleteServiceAccount(t.Context(), connect.NewRequest(&configpb.DeleteServiceAccountRequest{Id: "UNKNOWN"}))
	assert.NoError(t, err, "should allow deletion of service accounts which don't exist")
	_, err = client.DeleteServiceAccount(t.Context(), connect.NewRequest(&configpb.DeleteServiceAccountRequest{Id: "s-1000"}))
	assert.NoError(t, err)

	listRes, err = client.ListServiceAccounts(t.Context(), connect.NewRequest(&configpb.ListServiceAccountsRequest{
		Limit:   new(uint64(10)),
		OrderBy: new("-id"),
	}))
	if assert.NoError(t, err) {
		assert.Len(t, listRes.Msg.ServiceAccounts, 10)
		assert.Equal(t, uint64(999), listRes.Msg.TotalCount)
		assert.Equal(t, "s-0999", listRes.Msg.ServiceAccounts[0].GetId(), "should delete the last service account")
	}

	s := proto.CloneOf(listRes.Msg.ServiceAccounts[0])
	s.Description = new("service-account-0999-description-updated")
	updateRes, err := client.UpdateServiceAccount(t.Context(), connect.NewRequest(&configpb.UpdateServiceAccountRequest{
		ServiceAccount: s,
	}))
	assert.NoError(t, err)

	assert.NotEmpty(t, updateRes.Msg.Jwt,
		"should return a new jwt on update")

	getRes, err = client.GetServiceAccount(t.Context(), connect.NewRequest(&configpb.GetServiceAccountRequest{
		Id: "s-0999",
	}))
	if assert.NoError(t, err) {
		assert.Equal(t, "service-account-0999-description-updated", getRes.Msg.GetServiceAccount().GetDescription())
		assert.NotEmpty(t, cmp.Diff(s.GetModifiedAt(), getRes.Msg.GetServiceAccount().GetModifiedAt(), protocmp.Transform()),
			"should update the modified at timestamp")
	}
}

func TestConfigServiceSettings(t *testing.T, client configconnect.ConfigServiceClient) {
	t.Helper()

	_, err := client.UpdateSettings(t.Context(), connect.NewRequest(&configpb.UpdateSettingsRequest{
		Settings: &configpb.Settings{
			Id:       new("78408adf-56e4-41d0-af6a-ca1b2d8d2cb6"),
			Services: new("<INVALID>"),
		},
	}))
	assert.Equal(t, connect.CodeInvalidArgument.String(), connect.CodeOf(err).String(), "should validate settings")
}
