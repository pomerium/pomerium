package ssh_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
	mock_ssh "github.com/pomerium/pomerium/pkg/ssh/mock"
)

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestStreamManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	auth := mock_ssh.NewMockAuthInterface(ctrl)

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.Policies = []config.Policy{
		{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://dest1:22")},
		{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://dest2:22")},
	}
	m := ssh.NewStreamManager(auth, cfg)
	// intentionally don't call m.Run() - simulate initial sync completing
	m.ClearRecords(t.Context())
	t.Run("LookupStream", func(t *testing.T) {
		assert.Nil(t, m.LookupStream(1234))
		sh := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
		done := make(chan error)
		ctx, ca := context.WithCancel(t.Context())
		go func() {
			done <- sh.Run(ctx)
		}()
		assert.Equal(t, sh, m.LookupStream(1234))
		sh.Close()
		assert.Nil(t, m.LookupStream(1234))
		ca()
		err := <-done
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("TerminateStreamOnSessionDelete", func(t *testing.T) {
		sh := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
		done := make(chan error)
		go func() {
			done <- sh.Run(t.Context())
		}()

		m.SetSessionIDForStream(1234, "test-id-1")
		m.UpdateRecords(t.Context(), 0, []*databroker.Record{
			{
				Type: "type.googleapis.com/session.Session",
				Id:   "test-id-1",
				Data: marshalAny(&session.Session{}),
			},
			{
				Type:      "type.googleapis.com/session.Session",
				Id:        "test-id-1",
				Data:      marshalAny(&session.Session{}),
				DeletedAt: timestamppb.Now(),
			},
		})
		select {
		case err := <-done:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})

	t.Run("TerminateMultipleStreamsForSession", func(t *testing.T) {
		sh1 := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 1})
		done1 := make(chan error)
		go func() {
			done1 <- sh1.Run(t.Context())
		}()
		sh2 := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 2})
		done2 := make(chan error)
		go func() {
			done2 <- sh2.Run(t.Context())
		}()
		m.SetSessionIDForStream(1, "test-id-1")
		m.SetSessionIDForStream(2, "test-id-1")
		m.UpdateRecords(t.Context(), 0, []*databroker.Record{
			{
				Type: "type.googleapis.com/session.Session",
				Id:   "test-id-1",
				Data: marshalAny(&session.Session{}),
			},
			{
				Type:      "type.googleapis.com/session.Session",
				Id:        "test-id-1",
				Data:      marshalAny(&session.Session{}),
				DeletedAt: timestamppb.Now(),
			},
		})
		select {
		case err := <-done1:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
		select {
		case err := <-done2:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})

	t.Run("ClearRecords", func(t *testing.T) {
		sh1 := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 1})
		done1 := make(chan error)
		go func() {
			done1 <- sh1.Run(t.Context())
		}()
		sh2 := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 2})
		done2 := make(chan error)
		go func() {
			done2 <- sh2.Run(t.Context())
		}()
		m.SetSessionIDForStream(1, "test-id-1")
		m.SetSessionIDForStream(2, "test-id-2")
		m.ClearRecords(t.Context())
		select {
		case err := <-done1:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
		select {
		case err := <-done2:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})
}
