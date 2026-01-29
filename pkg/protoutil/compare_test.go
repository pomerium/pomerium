package protoutil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestCompareFuncForFieldMask(t *testing.T) {
	t.Parallel()

	t.Run("enums", func(t *testing.T) {
		t.Parallel()

		fn, err := protoutil.CompareFuncForFieldMask[config.KeyPair](&fieldmaskpb.FieldMask{
			Paths: []string{"status"},
		})
		if assert.NoError(t, err) {
			assert.Equal(t, 0, fn(&config.KeyPair{}, &config.KeyPair{}))
			assert.Equal(t, 0, fn(&config.KeyPair{Status: config.KeyPairStatus_KEY_PAIR_STATUS_READY}, &config.KeyPair{Status: config.KeyPairStatus_KEY_PAIR_STATUS_READY}))
			assert.Equal(t, -1, fn(&config.KeyPair{Status: config.KeyPairStatus_KEY_PAIR_STATUS_READY}, &config.KeyPair{Status: config.KeyPairStatus_KEY_PAIR_STATUS_PENDING}))
		}
	})
	t.Run("messages", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		later := now.Add(time.Second)

		fn, err := protoutil.CompareFuncForFieldMask[config.KeyPair](&fieldmaskpb.FieldMask{
			Paths: []string{"created_at"},
		})
		if assert.NoError(t, err) {
			assert.Equal(t, 0, fn(&config.KeyPair{}, &config.KeyPair{}))
			assert.Equal(t, 0, fn(&config.KeyPair{CreatedAt: timestamppb.New(now)}, &config.KeyPair{CreatedAt: timestamppb.New(now)}))
			assert.Equal(t, -1, fn(&config.KeyPair{CreatedAt: timestamppb.New(now)}, &config.KeyPair{CreatedAt: timestamppb.New(later)}))
		}
	})
	t.Run("strings", func(t *testing.T) {
		t.Parallel()

		fn, err := protoutil.CompareFuncForFieldMask[config.KeyPair](&fieldmaskpb.FieldMask{
			Paths: []string{"name"},
		})
		if assert.NoError(t, err) {
			assert.Equal(t, 0, fn(&config.KeyPair{}, &config.KeyPair{}))
			assert.Equal(t, 0, fn(&config.KeyPair{Name: proto.String("a")}, &config.KeyPair{Name: proto.String("a")}))
			assert.Equal(t, -1, fn(&config.KeyPair{Name: proto.String("a")}, &config.KeyPair{Name: proto.String("b")}))
			assert.Equal(t, 1, fn(&config.KeyPair{Name: proto.String("c")}, &config.KeyPair{Name: proto.String("b")}))
		}
	})
	t.Run("embedded", func(t *testing.T) {
		t.Parallel()

		fn, err := protoutil.CompareFuncForFieldMask[config.CertificateInfo](&fieldmaskpb.FieldMask{
			Paths: []string{"issuer.common_name"},
		})
		if assert.NoError(t, err) {
			assert.Equal(t, 0, fn(&config.CertificateInfo{}, &config.CertificateInfo{}))
			assert.Equal(t, 0, fn(&config.CertificateInfo{Issuer: &config.Name{CommonName: "x"}}, &config.CertificateInfo{Issuer: &config.Name{CommonName: "x"}}))
			assert.Equal(t, -1, fn(&config.CertificateInfo{Issuer: &config.Name{CommonName: "x"}}, &config.CertificateInfo{Issuer: &config.Name{CommonName: "y"}}))
		}
	})
	t.Run("repeated", func(t *testing.T) {
		t.Parallel()

		fn, err := protoutil.CompareFuncForFieldMask[config.CertificateInfo](&fieldmaskpb.FieldMask{
			Paths: []string{"dns_names"},
		})
		if assert.NoError(t, err) {
			assert.Equal(t, 0, fn(&config.CertificateInfo{}, &config.CertificateInfo{}))
			assert.Equal(t, 0, fn(&config.CertificateInfo{DnsNames: []string{"a", "b", "c"}}, &config.CertificateInfo{DnsNames: []string{"a", "b", "c"}}))
			assert.Equal(t, -1, fn(&config.CertificateInfo{DnsNames: []string{"a", "b", "c"}}, &config.CertificateInfo{DnsNames: []string{"a", "b"}}))
			assert.Equal(t, 1, fn(&config.CertificateInfo{DnsNames: []string{"a", "b"}}, &config.CertificateInfo{DnsNames: []string{"a", "b", "c"}}))
			assert.Equal(t, -1, fn(&config.CertificateInfo{DnsNames: []string{"a", "b", "b"}}, &config.CertificateInfo{DnsNames: []string{"a", "b", "c"}}))
		}
	})
}
