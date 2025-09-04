package config_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestDNSOptions_FromToProto(t *testing.T) {
	t.Parallel()

	// settings that go both directions
	for _, tc := range []struct {
		proto   *configpb.Settings
		options config.DNSOptions
	}{
		{
			&configpb.Settings{DnsFailureRefreshRate: durationpb.New(3 * time.Second)},
			config.DNSOptions{FailureRefreshRate: ptr(3 * time.Second)},
		},
		{
			&configpb.Settings{DnsLookupFamily: ptr("V4_ONLY")},
			config.DNSOptions{LookupFamily: config.DNSLookupFamilyV4Only},
		},
		{
			&configpb.Settings{DnsQueryTimeout: durationpb.New(4 * time.Second)},
			config.DNSOptions{QueryTimeout: ptr(4 * time.Second)},
		},
		{
			&configpb.Settings{DnsQueryTries: proto.Uint32(17)},
			config.DNSOptions{QueryTries: null.Uint32From(17)},
		},
		{
			&configpb.Settings{DnsRefreshRate: durationpb.New(5 * time.Second)},
			config.DNSOptions{RefreshRate: ptr(5 * time.Second)},
		},
		{
			&configpb.Settings{DnsUdpMaxQueries: proto.Uint32(111)},
			config.DNSOptions{UDPMaxQueries: null.Uint32From(111)},
		},
		{
			&configpb.Settings{DnsUseTcp: proto.Bool(true)},
			config.DNSOptions{UseTCP: null.BoolFrom(true)},
		},
	} {
		from := config.DNSOptions{}
		from.FromProto(tc.proto)
		assert.Empty(t, cmp.Diff(tc.options, from))

		to := new(configpb.Settings)
		tc.options.ToProto(to)
		assert.Empty(t, cmp.Diff(tc.proto, to, protocmp.Transform()))
	}
}

func TestDNSOptions_Validate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		options config.DNSOptions
		err     error
	}{
		{config.DNSOptions{}, nil},
		{config.DNSOptions{FailureRefreshRate: ptr(time.Microsecond)}, config.ErrDNSFailureRefreshRateTooShort},
		{config.DNSOptions{FailureRefreshRate: ptr(time.Millisecond)}, nil},
		{config.DNSOptions{LookupFamily: "<INVALID>"}, config.ErrUnknownDNSLookupFamily},
		{config.DNSOptions{RefreshRate: ptr(time.Microsecond)}, config.ErrDNSRefreshRateTooShort},
		{config.DNSOptions{RefreshRate: ptr(time.Millisecond)}, nil},
	} {
		err := tc.options.Validate()
		if tc.err == nil {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, tc.err)
		}
	}
}

func ptr[T any](v T) *T {
	return &v
}
